
<p align="center"><img src="https://0xsp.com/wp-content/uploads/2026/05/dcb03599ee1b43d7b622dafb4f16db16.png" width="700" alt="Aether logo"></p> 

<br>

# Aether 

version : 0.9 (stable release)

**Aether** is a Windows memory-forensics and threat hunting tool that scans live process
memory for malicious pattern, detect injection techniques, implant signatures, reflectively loaded
.NET assemblies. it works with a multi-layer confidence model that dramatically reduce the false
positive rate and hunt for malicious behaviour. Aether has good capabilities in detecting Hollowing, APC, thread hijacking techniques. Security analysts can use it to scan,hunt and snapshot suspicious region for offline analysis. 

Docs: https://0xsp.com/docs/aether-getting-started/
Blogpost: https://0xsp.com/security%20research%20%20development%20srd/aether-memory-forensics-and-threat-hunting-tool/ 

## Core Features
quick explainations for Aether core features, you can read the full technical blogpost to get more insights: 

### Signature Scanning
- **Byte-pattern matching** across process memory with a **first-byte index**
  that provides 50-100x speedup over naive scanning
- **ASCII + UTF-16LE dual encoding** — catches strings stored by the .NET CLR
  (where `"msxsl:script"` becomes `6D 00 73 00 78 00 ...`)
- **Dynamic rule loading** from JSON files — drop new signatures into `rules/`
  without recompilation
- **PE header detection** in `MEM_PRIVATE` regions — flags reflectively loaded
  .NET assemblies (`MZ` + `PE` + `BSJB` metadata)

### Structural Memory IOCs

Aether layers **five filters** on top of the raw
working-set signal so a finding requires multiple agreeing indicators
before it is reported with FP filtering:

| Layer | Filter | Purpose |
|-------|--------|---------|
| **L1** | Structural | Only **executable** IMAGE sub-regions are considered (eliminates `.data` / `.rdata` COW noise) |
| **L2** | Quantitative | Grade by `private_pages` count and `private_ratio` (low / medium / high) |
| **L3** | Corroboration | Promote only if an **independent** signal agrees on the same allocation base — signature hit, `missing_peb_entry`, `private_rwx`, hook prologue, or on-disk diff |
| **L4** | CLR-aware | Per-module suppression for ngen / R2R / tiered-JIT targets (`*.ni.dll`, `mscor*`, `clr*`, `coreclr`, `system.private.corelib*`) instead of blanket-skipping when the CLR is loaded |
| **L5** | On-disk diff | Map the module file with `CreateFileMappingW(SEC_IMAGE_NO_EXECUTE)`; compare the first 16 bytes of each private executable page against the same RVA on disk. Any divergence is a real-modification IOC |

Other structural checks:

- **PEB module cross-reference** : `MEM_IMAGE` allocations that are not in
  the PEB module list (DLL hollowing / module stomping)
- **Working-set scan** : modified-code page detection via
  `K32QueryWorkingSetEx`, **batched** with one syscall per region instead
  of one per 4 KB page (≈ 50-100× faster than the naïve loop)
- **Private RWX detection** : flags `MEM_PRIVATE + PAGE_EXECUTE_*` (it produces FP results) 
  allocations (shellcode, JIT spray, dynamic code stub allocations)
- **Hook-prologue probe** — reads the first 16 bytes of each private code
  page and matches classic x86/x64 trampolines:
  - `E9 ?? ?? ?? ??` — `JMP rel32`
  - `FF 25 ?? ?? ?? ??` — `JMP [rip+disp32]`
  - `68 ?? ?? ?? ?? C3` — `PUSH imm32 ; RET`
  - `48 B8 ?? ?? ?? ?? ?? ?? ?? ?? FF E0` — `MOV RAX, imm64 ; JMP RAX`
  - `49 BB ?? ?? ?? ?? ?? ?? ?? ?? 41 FF E3` — Detours-style
    `MOV R11, imm64 ; JMP R11` 
- **CLR detection** — section-object probe for `Cor_Private_IPCBlock_v4_<PID>`
  *and* the v2 `Cor_Private_IPCBlock_<PID>` (legacy .NET 2/3 / mscorwks),
  so noisy app-pools running old runtimes are not misclassified

### Thread Start-Address Validation (TSAV / L8)

Aether checks threads with stricter classification and
cross-correlation against the L1–L5 findings. For every created thread in the
target process Aether reads its `Win32StartAddress` via `NtQueryInformationThread`
and, when access permits, also the live `Rip` / `Eip` via
`GetThreadContext` / `Wow64GetThreadContext`. 
Each address is then graded as the following table, for more details read the blogpost:

| Verdict | Severity | Condition |
|---------|----------|-----------|
| `TSAV_SHELLCODE_PRIVATE` | CRITICAL | Address lives in a `MEM_PRIVATE + PAGE_EXECUTE_*` region — classic `CreateRemoteThread` shellcode |
| `TSAV_SUSPENDED_RIP` | CRITICAL | Suspended thread's `Rip` disagrees with `Win32StartAddress` and resolves to a suspicious region — catches `Win32StartAddress` spoofing (EarlyBird / APC tricks) and `SetThreadContext` hijacks |
| `TSAV_HOLLOWED_HOST` | HIGH | Address inside a `MEM_IMAGE` allocation that is not in the PEB module list (DLL hollowing / module stomping) |
| `TSAV_MODIFIED_HOST` | HIGH | Address inside a `MEM_IMAGE` allocation that the L1–L5 pipeline already flagged as `MODIFIED_CODE_*`, `MISSING_PEB`, `PRIVATE_RWX`, `DISK_MEM_DIFF`, or `HOOK_PROLOGUE` |
| `TSAV_STAGED_PRIVATE_RW` | HIGH | `MEM_PRIVATE + PAGE_READWRITE` — pre-`VirtualProtect` shellcode staging |
| `TSAV_MAPPED_NONPE` | MEDIUM | `MEM_MAPPED` (pagefile-backed section) without a PE header — sRDI / pagefile reflective loader |
| `TSAV_SPOOF_TRAMPOLINE` | MEDIUM | Address matches a denylisted trampoline (`LoadLibraryA/W/ExA/W`, `WinExec`, `CreateProcessA/W`, `VirtualAlloc[Ex]`, `RtlExitUserThread`, `RtlExitUserProcess`, `NtTerminateProcess`, `ShellExecuteA/W`) |

What makes this stronger than the basic check "is start_address in any module"
check:

- **`VirtualQueryEx` cross-check** — every address is queried for `Type` /
  `Protect` / `AllocationBase` in a single O(1) call instead of a linear
  scan over the module list
- **Cross-correlation with L1–L5** — a thread whose start lands inside an
  already-flagged allocation is upgraded from "OK" to `TSAV_MODIFIED_HOST`
- **PEB consistency** — hollowed modules are detected even when the start
  address technically falls inside a "real" range
- **Suspended-RIP probe** — `Win32StartAddress` is process-writable via
  `NtSetInformationThread` and is the spoofable field; the live `Rip` of a
  suspended thread is the one a loader can't easily rewrite. We compare
  the two and flag any disagreement that resolves to a suspicious region
- **WoW64 aware** — automatically switches to `Wow64GetThreadContext` and
  reads `Eip` for 32-bit threads inside a 64-bit process
- **Access-rights ladder** — falls back from `QUERY_INFORMATION |
  GET_CONTEXT` → `QUERY_INFORMATION` → `QUERY_LIMITED_INFORMATION` per
  thread, so partial-access scenarios still produce useful classifications

### L9 + L10 - Heap API-Table Detection with Cross-Module Correlation
Runtime API resolution is a technique frequently used by malware. Aether detection mechanism identifies this behavior by scanning the heap for valid module addresses and pointers, and correlating the results with the filtering criteria described below:

Each filter kills a specific FP class observed in real-world telemetry:

| Filter | Rule | FP class it removes |
|---|---|---|
| F1 | `count >= 5` | random pointer-shaped data, NULL, HMODULES |
| F2 | reject runs that point only into the host EXE | application-class C++ vtables |
| F3 | `distinct_modules >= 2` | single-DLL framework vtables (Qt, MFC, wxWidgets) |
| F4 | `capability_modules >= 2` | browser / CRT vtables that touch a single OS DLL (e.g. `iertutil + ucrtbase + shlwapi`) |
| F5 (L10) | `>= 80%` of checkable pointers land on **exported** RVAs | Winsock LSP dispatch tables, plugin callback arrays, vtables pointing at internal (non-exported) methods |
  

### Entropy analysis & Shellcode heuristics 

Aether supports XOR detection pattern at stub level for now and adopt Shannon entropy alogrithm to check randomness of byte values in memory region, it flags everything above a threshold. to address high amount of FP, Aether uses multiple indicators.

### C2 Beacon Detection
- **TCP connection monitoring** — polls `GetExtendedTcpTable` for a target PID
- **Beacon pattern detection** — identifies periodic short-lived connections
  (classic C2 callback behavior)
- **Connection table output** — formatted console table with state, endpoint,
  hits, and protocol

### Output Modes
- **Colored console report** with severity-based ANSI highlighting
- **Machine-parseable JSON** for SIEM / d-tect.py pipeline integration
- **Graded suspicion output** — each `MODIFIED_CODE_*` finding carries
  `private_pages` and `region_pages` so triage has the actual numbers
- **Table-formatted output** using Unicode box-drawing characters for
  connection monitoring

## Usage

```
Aether.exe --scan --pid <PID> [OPTIONS]
Aether.exe --scan --lookup "ProcessName.exe"
Aether.exe --hunt <PID> SLEEP_MS PERIOD
Aether.exe --scan-all [OPTIONS]
```

### Options

| Flag | Description |
|------|-------------|
| `--pid`, `-p <PID>` | Target process ID to scan |
| `--lookup`, `-l <name>` | Find all PIDs matching a process name |
| `--json`, `-j` | Output results as JSON (for SIEM integration) |
| `--verbose`, `-v` | Show per-region scan details |
| `--scan-all`, `-a` | Scan all processes  |
| `--hunt`, `-b <PID> [ms] [hits]` | Monitor connections — poll every `ms` (default 2000), flag endpoints with ≥ `hits` occurrences |
| `--networking` | Network-monitoring mode |
| `--rules`, `-r <dir>` | Rules directory (default: `rules/`) |
| `--config`, `-c <file>` | Single rule file (legacy format) |
| `--dump`, `` | Dump specific memory region with custom size |
| `--read`, `` | Read memory region content live on terminal |
| `--help`, `-h` | Show help |

## How to Compile

### Prerequisites

- **Zig 0.16** — [download here](https://ziglang.org/download/)
- Cross-compilation works from any host OS (Linux, macOS, Windows)

### Build

```bash
git clone https://github.com/0xsp-SRD/aether
cd aether

# Debug build (safety checks enabled)
zig build

# Release build (smaller, faster binary)
zig build -Doptimize=ReleaseSafe
# or
zig build -Doptimize=ReleaseFast
```

The built executable lands in `zig-out/bin/Aether.exe`.


### Deploy

Copy `zig-out/bin/Aether.exe` and the `rules/` directory to the target
Windows machine if you want to perform additional signature scan. if the target process requires Administrative privileges, you need to run Aether.exe with Administrator privileges. 


## Limitations

- **Usermode only** — no kernel driver; cannot detect rootkits or
  kernel-level manipulations
- **IPv4 only** — TCP connection monitoring does not support IPv6 endpoints for now.
- **L5 disk diff requires file access** — if the original module file has
  been deleted or is locked, the on-disk diff silently skips that module
  (other layers still run)
- **TSAV spoof-trampoline list resolves in the scanner's own process** —
  catches the common case where system DLLs share an ASLR base session-wide
  but may miss targets with unique per-process bases (rare on Win10+)
- **TSAV RIP probe only catches suspended threads** — a `Win32StartAddress`
  rewrite on an already-running thread can only be detected if the thread
  happens to be parked in a wait when probed (same constraint as Moneta)
- **XOR-PE detection is basic on this release** 


## License
Aether is open-source software licensed under the GNU General Public License v3.0 (GPLv3).
