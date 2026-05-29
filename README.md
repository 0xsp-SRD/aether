
<p align="center"><img src="https://0xsp.com/wp-content/uploads/2026/05/dcb03599ee1b43d7b622dafb4f16db16.png" width="700" alt="Aether logo"></p> 

<br>

# Aether 

version : 0.8 (public beta)

**Aether** is a Windows memory-forensics and threat hunting tool that scans live process
memory for malicious pattern, detect injection techniques, implant signatures, reflectively loaded
.NET assemblies. it works with a multi-layer confidence model that dramatically reduce the false
positive rate and hunt for malicious behaviour. Aether has good capabilities in detecting Hollowing, APC, thread hijacking techniques. Security analysts can use it to scan,hunt and snapshot suspicious region for offline analysis. 


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


## Suspicion Types

### Modified-code pipeline (L1–L5)

| Label | Severity | Meaning |
|-------|----------|---------|
| `MODIFIED_CODE_HIGH` | HIGH | Executable IMAGE pages with hook prologue, on-disk diff, OR ≥ 25 % private-page ratio |
| `MODIFIED_CODE_MED` | MEDIUM | Corroborated by another signal, OR ≥ 5 % ratio, OR ≥ 8 private pages |
| `HOOK_PROLOGUE` | MEDIUM | Trampoline byte pattern found at the start of a private code page |
| `DISK_MEM_DIFF` | HIGH | First bytes of an executable private page differ from the on-disk image |
| `MISSING_PEB` | HIGH | `MEM_IMAGE` allocation not present in the PEB module list (DLL hollowing) |
| `PRIVATE_RWX` | HIGH | Private memory with executable protection |
| `CLR_INIT` | INFO | Target process hosts the .NET CLR (filtering hint, not a finding) |

### Thread Start-Address Validation (L8)

| Label | Severity | Meaning |
|-------|----------|---------|
| `TSAV_SHELLCODE_PRIVATE` | CRITICAL | Thread starts in `MEM_PRIVATE + PAGE_EXECUTE_*` (classic shellcode thread) |
| `TSAV_SUSPENDED_RIP` | CRITICAL | Suspended thread's `Rip` / `Eip` resolves to a suspicious region disagreeing with `Win32StartAddress` |
| `TSAV_HOLLOWED_HOST` | HIGH | Thread starts inside a `MEM_IMAGE` allocation missing from the PEB |
| `TSAV_MODIFIED_HOST` | HIGH | Thread starts inside an allocation already flagged by L1–L5 |
| `TSAV_STAGED_PRIVATE_RW` | HIGH | Thread starts in `MEM_PRIVATE + PAGE_READWRITE` (pre-`VirtualProtect` staging) |
| `TSAV_MAPPED_NONPE` | MEDIUM | Thread starts in `MEM_MAPPED` non-PE section |
| `TSAV_SPOOF_TRAMPOLINE` | MEDIUM | Thread `Win32StartAddress` equals a denylisted trampoline (`LoadLibraryW`, `RtlExitUserThread`, etc.) |
| `THREAD_START_ANOMALY` | HIGH | Aggregate count of suspicious threads (one per scan) |

### Encrypted Payload Detection

| Label | Severity | Meaning |
|-------|----------|---------|
| `XOR_PE_HEADER` | CRITICAL | PE header found under single- or multi-byte XOR; DOS-stub anchor + `MZ` / `e_lfanew` / `PE\0\0` consistency check all pass (Donut, CS `sleep_mask`, Sliver, sRDI) |


## Rule Packs

Signatures are organised into JSON rule packs. Drop any of these into the
`rules/` directory:

| File | Coverage |
|------|----------|
| `cobalt_strike.json` | Cobalt Strike beacon artifacts |
| `meterpreter.json` | Metasploit Meterpreter implant |
| `sliver.json` | Sliver C2 implant (BishopFox) |
| `brute_ratel.json` | Brute Ratel C4 badger |
| `havoc.json` | Havoc C2 demon |
| `sharp_tools.json` | .NET offensive tools (Rubeus, Seatbelt, SharpHound) |
| `mimikatz.json` | Mimikatz credential theft |
| `powershell_cradles.json` | PowerShell attack cradles & AMSI bypass |
| `dotnet_loaders.json` | Generic .NET loaders & injectors |
| `mythic_poshc2.json` | Mythic / PoshC2 / Nighthawk implants |
| `phantom_str.json` | Phantom ASP .NET loader |

Each rule file is a JSON array of signature objects:

```json
[
  {
    "pattern": "msxsl:script",
    "weight": 5,
    "category": "engine_xslt",
    "description": "XSLT script block declaration"
  }
]
```

`category` maps to one of: `engine_xslt`, `engine_codedom`, `engine_managed`,
`c2_tcp`, `c2_http`, `c2_sql`, `c2_smtp`, `c2_file`, `c2_dns`, `evasion`,
`reflective_load`, `webshell_generic`.


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
| `--help`, `-h` | Show help |


## Sample Output

### Console Report
```
  Scan Results for PID 4820
  ==================================================
  Regions: 847 total, 312 scanned, 287 system-skipped
  Bytes scanned: 214.35 MB
  Read errors: 3
  Scan time: 1247 ms

  [HIGH] ENGINE_XSLT | score=18 hits=4 [T1220]
    +5 "msxsl:script" @ 0x7FFE2A3B1000 (ascii)
    +6 "urn:payload"  @ 0x7FFE2A3B1200 (ascii)
    +4 "enableScript" @ 0x7FFE2A3B1400 (utf16le)
    +3 "XsltSettings" @ 0x7FFE2A3B1600 (ascii)

  [CRITICAL] REFLECTIVE_LOAD | 2 PE headers in MEM_PRIVATE
    (1 with .NET BSJB metadata) [T1620]

  ---- Structural IOCs (8) ----
  [HIGH]     MISSING_PEB             @ 0x000001D6E0000000 (1048576 bytes)
  [HIGH]     DISK_MEM_DIFF           @ 0x000001D6E0001000 (4 private / 240 pages)
  [HIGH]     MODIFIED_CODE_HIGH      @ 0x000001D6E0001000 (4 private / 240 pages)
  [HIGH]     PRIVATE_RWX             @ 0x000001D6EDDD0000 (12288 bytes)
  [CRITICAL] XOR_PE_HEADER           @ 0x000001D6EDDD0000 (4 bytes)
  [CRITICAL] TSAV_SHELLCODE_PRIVATE  @ 0x000001D6EDDD0000 (8472 bytes)
  [HIGH]     TSAV_MODIFIED_HOST      @ 0x000001D6E0001000 (8476 bytes)
  [HIGH]     THREAD_START_ANOMALY    @ 0x0 (2 bytes)
```

With `--verbose` you also see per-thread detail and recovered XOR keys:
```
  [!] XOR_PE_HEADER @ 0x1D6EDDD0000 key_len=4 key=AABBCCDD
  [!] TID:8472 SHELLCODE_PRIVATE start=0x1D6EDDD0150
  [!] TID:8476 MODIFIED_HOST     start=0x1D6E0001A80 host=msi.dll
```

The recovered key bytes can be passed to a one-liner (`python -c 'import
sys; k=bytes.fromhex("AABBCCDD"); d=sys.stdin.buffer.read(); sys.stdout.
buffer.write(bytes(b^k[i%len(k)] for i,b in enumerate(d)))'`) to dump
the decrypted PE for analysis.


## How to Compile

### Prerequisites

- **Zig 0.16** — [download here](https://ziglang.org/download/)
- Cross-compilation works from any host OS (Linux, macOS, Windows)

### Build

```bash
git clone https://github.com/
cd Aether

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


## Why Zig?

| Property | Benefit |
|----------|---------|
| **No runtime, no GC** | Single ~1 MB `.exe` — deploy anywhere |
| **Direct C FFI** | `extern "kernel32" fn ...` — zero-overhead Win32 calls |
| **Cross-compilation** | Build Windows `.exe` from Linux or macOS |
| **Compile-time safety** | Out-of-bounds, null pointer, integer overflow caught before deployment |
| **`defer` / `orelse` / `try`** | Clean, deterministic resource management — no exceptions, no RAII |
| **`comptime`** | Format strings type-checked, first-byte index built at compile time |


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
