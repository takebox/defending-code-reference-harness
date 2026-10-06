# Candidate Patches

> **Static review only.** These diffs were authored and reviewed by
> independent agents reading source. They were NOT compiled, run, or
> re-attacked. Read each diff yourself before applying — see
> `docs/patching.md#reviewing-generated-patches` for what to look for.

**Input:** TRIAGE.json · **Repo:** targets/canary · 3 findings → 3 diffs

---

## bug_00: [HIGH] Heap buffer overflow via input-controlled copy length in parse_alpha  (f001)

`entry.c:27` · heap-buffer-overflow
**Status:** static_review_only · review ACCEPT · style 8/10
**Diff:** `PATCHES/bug_00/patch.diff` (1 hunk, 5 lines)

**Rationale:** Root cause: entry.c:23 assigns claimed from untrusted input with no upper bound, and entry.c:27 passes it directly as the memcpy length into an 8-byte heap allocation. The fix clamps claimed to the allocation size (8) and to the available source bytes (len - 1) immediately after the allocation null-check, before the memcpy.
**Variants checked:** entry.c:parse_bravo -- uses memcpy(name, buf, len) with the caller-supplied len, not an embedded length field. Different bug class (stack-buffer-overflow), different root cause pattern. Not addressed by this fix. entry.c:parse_charlie -- no memcpy; UAF bug, unrelated pattern.
**Bypass considered:** An attacker sets buf[0] = 255 (claimed = 255). The first clamp reduces it to 8. The attacker then provides exactly 2 bytes of input (len = 2, so len - 1 = 1). The second clamp reduces claimed to 1. The memcpy writes 1 byte into the 8-byte buffer -- safe.

---

## bug_01: [HIGH] Stack buffer overflow via unbounded memcpy in parse_bravo  (f002)

`entry.c:40` · stack-buffer-overflow
**Status:** static_review_only · review ACCEPT · style 9/10
**Diff:** `PATCHES/bug_01/patch.diff` (1 hunk, 5 lines)

**Rationale:** Root cause: entry.c:40 -- memcpy(name, buf, len) copies a caller-controlled length (up to 4095) into a 16-byte stack buffer with no bounds check. The fix clamps len to sizeof(name) - 1 (15) before the copy.
**Variants checked:** entry.c:parse_alpha -- same unchecked-memcpy pattern (line 27, heap target). Separate finding (f001). entry.c:parse_charlie -- no memcpy, not applicable.
**Bypass considered:** An attacker supplies exactly 16 bytes of payload (len=15 after the dispatcher subtracts 1). After the clamp, 15 == sizeof(name) - 1, so the condition is false and len stays 15. memcpy writes bytes 0-14, then name[15] is set to '\0'. No overflow.

---

## bug_02: [HIGH] Heap use-after-free via missing return after conditional free in parse_charlie  (f003)

`entry.c:60` · use-after-free
**Status:** static_review_only · review ACCEPT · style 9/10
**Diff:** `PATCHES/bug_02/patch.diff` (1 hunk, 3 lines)

**Rationale:** Root cause is entry.c:58 -- free(r) inside the conditional block lacks a return, so execution falls through to entry.c:60 which dereferences the freed pointer. Adding return immediately after free(r) terminates the early-free path before the dangling write.
**Variants checked:** entry.c:parse_alpha -- single free at function end, no conditional-free-without-return pattern. entry.c:parse_bravo -- stack buffer only, no heap allocation, not applicable.
**Bypass considered:** An attacker tries buf[0]=0xff to trigger the early-free path. With the fix, that path returns immediately after free(r), so line 60 is never reached. Any other value of buf[0] skips the free entirely, so r is live when line 60 executes.

---
