# Threat Model: canary

## 1. System context

Canary is a deliberately vulnerable C program (single file, ~87 lines) designed as a fast-iteration smoke test for the vuln-pipeline. It compiles a binary (`/work/entry`) that reads a file from disk and dispatches to one of three "parsers" based on the first byte of input: `parse_alpha` ('A'), `parse_bravo` ('B'), and `parse_charlie` ('C'). Each parser contains one planted memory-safety bug with a distinct ASAN signature.

The target is not production code and has no upstream, no CVE history, and no real users. It runs inside a Docker container built from `gcc:14`, compiled with `-O1 -fsanitize=address -fno-omit-frame-pointer`. Its purpose is to validate pipeline stages (find, grade, dedup, report, patch) in ~6 minutes rather than hours against real codebases. The three bugs exercise heap-buffer-overflow, stack-buffer-overflow, and heap-use-after-free — covering the most common native memory corruption classes.

## 2. Assets

| asset | description | sensitivity |
|---|---|---|
| Process memory integrity | Native C code performs direct memory operations (malloc, memcpy, free) on attacker-controlled input. Memory corruption is the primary risk class. | critical |
| Host process integrity | Successful memory corruption can escalate to arbitrary code execution in the context of the process, which runs as root inside the container. | critical |
| Service availability | Any of the three bugs crashes the process. Repeated triggering constitutes denial of service. | medium |

## 3. Entry points & trust boundaries

| entry_point | description | trust_boundary | reachable_assets |
|---|---|---|---|
| File parsing (CLI input) | main() reads argv[1] via fopen/fread (up to 4096 bytes), dispatches by first byte to parse_alpha, parse_bravo, or parse_charlie. All input bytes are attacker-controlled. | untrusted file → process memory | Process memory integrity, Host process integrity, Service availability |
| Build/container supply chain | Dockerfile pulls gcc:14 (unpinned digest) and installs apt packages without version locks. Debug tools (gdb) included in image. No USER directive — runs as root. | upstream package repos → build artifacts → runtime container | Host process integrity |

## 4. Threats

| id | threat | actor | surface | asset | impact | likelihood | status | controls | evidence |
|---|---|---|---|---|---|---|---|---|---|
| T1 | Remote code execution via memory corruption in untrusted file parsing | local_user | File parsing (CLI input) | Process memory integrity, Host process integrity | critical | almost_certain | unmitigated | none | planted-alpha (heap-buffer-overflow in parse_alpha), planted-bravo (stack-buffer-overflow in parse_bravo), planted-charlie (heap-use-after-free in parse_charlie) |
| T2 | Denial of service via crash-inducing input to any parser | local_user | File parsing (CLI input) | Service availability | medium | almost_certain | unmitigated | none | planted-alpha, planted-bravo, planted-charlie |
| T3 | Information disclosure via out-of-bounds heap read during parsing | local_user | File parsing (CLI input) | Process memory integrity | high | possible | unmitigated | none | |
| T4 | Supply-chain compromise of build image or apt packages leading to backdoored binary | supply_chain | Build/container supply chain | Host process integrity | critical | rare | unmitigated | none | |
| T5 | Container escape via memory corruption combined with root-privileged process | local_user | File parsing (CLI input) | Host process integrity | critical | rare | partially_mitigated | gVisor (runsc) sandbox when run via vp-sandboxed | |

## 5. Deprioritized

| threat | reason |
|---|---|
| Spoofing: attacker impersonates a trusted input source | Not applicable — local CLI tool reads a file path from argv; no authentication or identity model exists. The file is the only input, and whoever can place a file already has local access. |
| Repudiation: attacker acts without leaving attributable logs | Not applicable — single-user CLI tool with no multi-user actions, no audit trail, and no logging beyond stdout/stderr. There is nothing to repudiate. |
| Tampering with data at rest | Not applicable — the binary reads a file and prints to stdout; it does not persist state, write to databases, or modify the input file. |

## 6. Open questions

- **Deployment context:** Is this binary ever exposed to network-delivered input (e.g., a web service writing uploaded files to disk and invoking `entry`)? If so, the actor for T1-T3 escalates from `local_user` to `remote_unauth`.
- **Intended actors:** Who supplies the input files in practice? If only pipeline-internal test harnesses, the residual risk is lower; if external users or untrusted data sources, the model stands as-is.
- **Upstream sandboxing:** Is there a size limit, format validation, or sandboxing layer upstream of the binary (e.g., seccomp, resource limits, read-only filesystem) that would constrain post-exploitation?
- **Risk appetite for DoS:** Is process crash acceptable for this use case (smoke test), or does the pipeline rely on the binary staying alive across multiple invocations?
- **Container runtime:** Is gVisor (runsc) always used, or can the binary run under the default runc runtime? The T5 likelihood score depends on this.

## 7. Provenance

- mode: bootstrap
- date: 2026-08-04
- target: targets/canary @ 6de8141
- inputs: git-log + CHANGELOG mined
- owner: unset

## 8. Recommended mitigations

| mitigation | threat_ids | closes_class | effort |
|---|---|---|---|
| Bounds-check all length fields and copy sizes against allocation/buffer sizes before any memcpy or write operation | T1, T2, T3 | yes | S |
| Run the parsing process as an unprivileged user (add USER directive to Dockerfile) and apply seccomp-bpf to restrict syscalls | T1, T5 | partial | S |
| Pin the base image digest and apt package versions in the Dockerfile | T4 | yes | S |
| Sandbox the parser in a separate process with minimal privileges so corruption cannot escalate beyond the sandbox | T1, T2, T3, T5 | partial | M |
