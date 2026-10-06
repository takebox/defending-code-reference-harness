# Vulnerability Findings: targets/canary

**Scanned:** 2026-08-04  
**Source files:** 1  
**Focus areas:** 3  
**Findings:** 5 (3 HIGH, 1 MEDIUM, 1 LOW — 1 low-confidence)

## Summary

| ID | Severity | Confidence | Category | Location | Title |
|---|---|---|---|---|---|
| F-001 | HIGH | 0.95 | heap-buffer-overflow | entry.c:27 | Heap buffer overflow via input-controlled copy length in parse_alpha |
| F-002 | HIGH | 0.95 | stack-buffer-overflow | entry.c:40 | Stack buffer overflow via unbounded memcpy in parse_bravo |
| F-003 | HIGH | 0.95 | use-after-free | entry.c:60 | Heap use-after-free via missing return after conditional free in parse_charlie |
| F-004 | LOW | 0.70 | uninitialized-read | entry.c:29 | Information disclosure via uninitialized heap read in parse_alpha when claimed length is zero |
| F-005 | MEDIUM | 0.50 | double-free | entry.c:62 | Potential double-free in parse_charlie when freed memory is reallocated |

---

### F-001 — Heap buffer overflow via input-controlled copy length in parse_alpha

- **Severity:** HIGH
- **Confidence:** 0.95
- **Category:** heap-buffer-overflow
- **Location:** entry.c:27

**Description:** parse_alpha allocates an 8-byte heap buffer at line 24 (`malloc(8)`) but copies an attacker-controlled number of bytes into it at line 27. The copy length `claimed` is taken directly from `buf[0]` (the second byte of the input file, since main dispatches `buf+1`), giving a range of 0–255. Any value of `claimed` greater than 8 causes memcpy to write past the end of the 8-byte allocation, corrupting adjacent heap metadata or objects.

**Exploit scenario:** An attacker crafts a file whose first byte is `'A'` (dispatch to parse_alpha) and second byte is `0xFF` (claimed length = 255). The remaining bytes are attacker-controlled payload. memcpy at line 27 writes 255 bytes into an 8-byte heap allocation, overwriting heap metadata and adjacent allocations. This can be leveraged for arbitrary write via heap metadata corruption, leading to code execution.

**Recommendation:** Bounds-check `claimed` against both the allocation size and the available input length before the memcpy: `if (claimed > 8) claimed = 8; if (claimed > len - 1) claimed = len - 1;`

---

### F-002 — Stack buffer overflow via unbounded memcpy in parse_bravo

- **Severity:** HIGH
- **Confidence:** 0.95
- **Category:** stack-buffer-overflow
- **Location:** entry.c:40

**Description:** parse_bravo declares a 16-byte stack buffer `name` at line 38 and copies the full input length into it at line 40 via `memcpy(name, buf, len)`. The `len` parameter comes from main as `(n - 1)` where `n` is up to 4096 bytes read from the input file. Any input starting with `'B'` that exceeds 17 bytes total (1 dispatch byte + 16 data bytes) overwrites the stack frame, including the return address.

**Exploit scenario:** An attacker crafts a file starting with `'B'` followed by 4095 bytes of payload. parse_bravo copies all 4095 bytes into the 16-byte stack buffer `name`, smashing the saved return address and other stack frames. A carefully crafted payload overwrites the return address to redirect execution to attacker-controlled code or a ROP chain.

**Recommendation:** Clamp the copy length to the buffer size: `size_t copy_len = len < sizeof(name) ? len : sizeof(name); memcpy(name, buf, copy_len);`

---

### F-003 — Heap use-after-free via missing return after conditional free in parse_charlie

- **Severity:** HIGH
- **Confidence:** 0.95
- **Category:** use-after-free
- **Location:** entry.c:60

**Description:** parse_charlie allocates a `struct record` on the heap at line 53. At line 56, if `r->id` equals `0xFF` (controlled by the second byte of the input file), the record is freed at line 58. However, the function does not return after the free — execution falls through to line 60 where `r->value` is written through the now-dangling pointer. This is a heap-use-after-free on a WRITE operation.

**Exploit scenario:** An attacker crafts a file whose first byte is `'C'` (dispatch to parse_charlie) and second byte is `0xFF` (triggers the early-free path). The third byte is the value written through the dangling pointer at line 60. If the freed memory has been reallocated to a security-sensitive structure (e.g., a vtable pointer or function pointer), the attacker-controlled write corrupts it, enabling code execution.

**Recommendation:** Add `return;` after `free(r)` at line 58, or restructure the control flow so the write at line 60 is unreachable after the free path.

---

### F-004 — Information disclosure via uninitialized heap read in parse_alpha when claimed length is zero

- **Severity:** LOW
- **Confidence:** 0.70
- **Category:** uninitialized-read
- **Location:** entry.c:29

**Description:** In parse_alpha, if the attacker-controlled `claimed` value (`buf[0]`) is 0, the memcpy at line 27 copies 0 bytes — a no-op. The subsequent printf at line 29 reads `out[0]` from the malloc'd but never-written 8-byte buffer, leaking one byte of heap content to stdout. While malloc does not guarantee zero-initialization, the leaked data is a single byte and the attacker already has local file access.

**Exploit scenario:** An attacker crafts a file with first byte `'A'` and second byte `0x00` (claimed = 0). parse_alpha allocates 8 bytes, copies nothing, then prints the uninitialized first byte of the heap allocation. This leaks one byte of heap state, which could aid heap layout analysis for a multi-stage exploit chain.

**Recommendation:** Initialize the allocated buffer before use: `memset(out, 0, 8);` or check that `claimed > 0` before proceeding to the printf.

---

### F-005 — Potential double-free in parse_charlie when freed memory is reallocated

- **Severity:** MEDIUM
- **Confidence:** 0.50
- **Category:** double-free
- **Location:** entry.c:62

**Description:** After the use-after-free at line 60 (F-003), parse_charlie reaches the conditional free at line 62: `if (r->id != 0xff) free(r)`. Under ASAN, quarantined memory preserves `r->id` as `0xFF` so the condition is false and the second free is skipped. Without ASAN (production binary), if the allocator reuses the freed memory between lines 58 and 60, `r->id` may be overwritten with a non-`0xFF` value, causing the condition at line 62 to be true and triggering a double-free on the same pointer. This is heap-state-dependent and only manifests in non-ASAN builds under specific allocation patterns.

**Exploit scenario:** In a production (non-ASAN) build, an attacker triggers the `0xFF` path in parse_charlie. Between the free at line 58 and the read at line 62, if another allocation (from printf or internal libc state) reuses the freed chunk and overwrites the `id` field, `r->id != 0xFF` evaluates to true, causing a second `free(r)`. The double-free corrupts heap metadata, which can be leveraged for arbitrary write primitives.

**Recommendation:** Fix the root cause (F-003) by adding `return;` after the free at line 58. This eliminates both the UAF and the double-free path.
