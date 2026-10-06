# Triage Report

5 in -> 1 duplicate, 0 false positives, 4 confirmed (3 high / 0 med / 1 low), 0 need manual test

Context: auto; environment = Production parser exposed to untrusted input files; scoring = derived HIGH/MEDIUM/LOW; 3-vote verification.

## Act on these

### [HIGH] Heap buffer overflow via input-controlled copy length in parse_alpha  (f001)
`entry.c:27` | heap-buffer-overflow | claimed HIGH (alignment +0) | confidence 10.0/10
**Verdict:** exploitable, votes 3/0/0 (TP/FP/CV)
**Preconditions (0):** none
**Threat-model match:** none
**Why:** parse_alpha at entry.c:23 reads claimed = buf[0] (range 0-255) from attacker-controlled input, allocates exactly 8 bytes at entry.c:24, then performs memcpy(out, buf + 1, claimed) at entry.c:27 with no bounds check. Any claimed > 8 writes past the heap allocation. The function is reachable from main() at entry.c:78 via the 'A' dispatch byte. No intervening validation exists. The write primitive is fully attacker-controlled in both length (0-255) and content.
**Reachability evidence:** entry.c:78

### [HIGH] Stack buffer overflow via unbounded memcpy in parse_bravo  (f002)
`entry.c:40` | stack-buffer-overflow | claimed HIGH (alignment +0) | confidence 10.0/10
**Verdict:** exploitable, votes 3/0/0 (TP/FP/CV)
**Preconditions (0):** none
**Threat-model match:** none
**Why:** parse_bravo declares char name[16] (line 38) and performs memcpy(name, buf, len) at line 40 with zero bounds checking. The sole caller is main() at entry.c:79, where len can reach 4095 — overflowing the 16-byte stack buffer by up to 4079 bytes. The overflow is stack-based with fully attacker-controlled content, directly overwriting the saved return address and enabling arbitrary code execution.
**Reachability evidence:** entry.c:79

### [HIGH] Heap use-after-free via missing return after conditional free in parse_charlie  (f003)
`entry.c:60` | use-after-free | claimed HIGH (alignment +0) | confidence 10.0/10
**Verdict:** exploitable, votes 3/0/0 (TP/FP/CV)
**Preconditions (0):** none
**Threat-model match:** none
**Why:** parse_charlie is reachable from main at entry.c:80 when the first input byte is 'C'. At entry.c:53 a struct record is heap-allocated; at entry.c:56-58, if r->id == 0xff (attacker-controlled via the second input byte), the record is freed with no subsequent return statement. Execution falls through to entry.c:60 where r->value = buf[1] writes through the dangling pointer. A deterministic 3-byte input file suffices. The attacker controls both the free trigger and the value written through the dangling pointer.
**Reachability evidence:** entry.c:80

### [LOW] Information disclosure via uninitialized heap read in parse_alpha when claimed length is zero  (f004)
`entry.c:29` | uninitialized-read | claimed LOW (alignment +0) | confidence 8.3/10
**Verdict:** exploitable, votes 3/0/0 (TP/FP/CV)
**Preconditions (1):**
- Attacker must be able to observe the program's stdout to capture the leaked heap byte
**Threat-model match:** none
**Why:** When the input file is 'A' \x00 <any>, parse_alpha is called (entry.c:78), claimed is 0 (line 23), memcpy copies zero bytes (line 27), and printf at line 29 reads out[0] from a malloc'd-but-never-written 8-byte buffer, leaking one byte of heap content to stdout. No guard or initialization protects this path. Impact is limited to a single-byte information disclosure per invocation — useful in a multi-stage exploit chain but not independently exploitable for code execution.
**Reachability evidence:** entry.c:78

## Dropped

| id | title | file:line | why dropped |
|----|-------|-----------|-------------|
| f005 | Potential double-free in parse_charlie when freed memory is reallocated between lines 58 and 62 | entry.c:62 | duplicate of f003 |
