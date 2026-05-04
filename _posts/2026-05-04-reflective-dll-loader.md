---
layout: post
title: "Rewriting the Reflective DLL Loader: A Walkthrough"
date: 2026-05-04
tags: [malware-dev, reflective-dll-injection, PE, evasion, red-team]
summary: "A walkthrough of a from-scratch rewrite of Stephen Fewer's ReflectiveLoader, covering PE parsing, indirect syscalls, PEB walking with djb2 hashing, and the bugs hit while debugging in WinDbg."
---

One of the areas I really enjoy working on and learning more about is malware development. I started years ago with [Sektor7](https://institute.sektor7.net/)'s Malware Development Essentials course and recently jumped into the Intermediate one. Overall, both courses are great and I definitely recommend them. On the intermediate course one area I found particularly interesting was reflective DLL injection. The course did a great job explaining it but I also saw it as an opportunity to challenge myself and understand it more deeply, and along the way to make some changes that align better with the current red team landscape.

So I started rewriting Fewer's [ReflectiveLoader](https://github.com/stephenfewer/reflectivedllinjection) from scratch. Same technique, different implementation. The goal was not novelty, given that reflective DLL injection has been public since 2009 and is documented everywhere. The goal was comprehension by parsing the PE format myself, resolving the imports myself, applying relocations myself, and tracing the result in WinDbg until every step made sense.

In this post, I will walk through the loader I built, what I changed from Fewer's version and why, plus the bugs I hit during debugging that I didn't expect.

**Credit where it's due**: The technique is Stephen Fewer's (Harmony Security, 2009). The original copyright notice is preserved in my headers. reenz0h's [Malware Development Intermediate](https://institute.sektor7.net/rto-maldev-intermediate) course at Sektor7 gave me the conceptual foundation to attempt the rewrite.

Code is on my GitHub at [https://github.com/ilkyr/CustomRDI](https://github.com/ilkyr/CustomRDI).

## What reflective loading actually does

A reflective loader is a function compiled into a DLL that allows the DLL to load itself into a process's memory without calling `LoadLibrary`. The DLL can be supplied entirely from memory and mapped without ever going through the Windows loader. Whether the bytes touch disk along the way depends on how the operator delivers them (embedded inside the loader binary, decrypted from a blob, pulled over the network, or, in this post's demo, read from a file path passed on the command line). What reflective loading really removes is the dependency on `LoadLibrary` to do the mapping.

Inside the target process, the reflective loader function performs the subset of loader work that gets the DLL into a runnable state: allocating memory, mapping PE sections, resolving imports, applying base relocations, setting per-section permissions, and calling `DllMain`. It does not replicate everything `ntdll!LdrLoadDll` does (loader-lock handling, TLS callbacks, activation contexts, PEB loader-list registration, API Set schema resolution, exception unwind metadata, and so on). Most payload DLLs run fine without those, especially the small `DllMain` runners typical in red team work, but it's good to know what is missing. There is a Limitations section near the end with the full list.

The full injection chain:

1. A payload DLL is compiled with the reflective loader function as an exported symbol alongside whatever payload logic you want to run on attach.
2. An outer loader program acquires the DLL's bytes into memory. In a real engagement this usually means the DLL is embedded (and usually encrypted) inside the loader binary so only one file touches the target. For this post's demo, the outer loader takes a file path on the command line and reads the DLL from disk. Delivery is a separate problem from reflective loading, and keeping it simple here keeps the walkthrough focused to the reflective loading.
3. The outer loader parses the in-memory DLL's export table to find the reflective loader function's file offset, marks the memory as executable, and creates a thread starting at that offset.
4. The reflective loader runs, maps the DLL into a fresh allocation, and calls `DllMain`, which triggers the payload.

Fewer's loader handles step 4. My `CustomLoader` is a drop-in replacement for that step.

## Design decisions: what I changed and why

Fewer's implementation works and has been battle-tested for over a decade. Honestly, what surprised me is how many modern "advanced" loaders get caught on small implementation details and not on the technique itself, while a careful implementation of Fewer's original idea still works in plenty of places. The changes below are about understanding the technique, and adding a few well-documented evasion ideas (indirect syscalls, API hashing) that have become common in offensive tooling since 2009. None of them are novel.

### Finding our own address with a dedicated asm stub

Fewer finds his own address by calling a non-inlined helper that returns the result of the `_ReturnAddress` intrinsic. It works but as Fewer notes in a comment in his source, RIP-relative addressing would be cleaner if the compiler intrinsics in x64 allowed it. They don't, so I dropped down to an external asm stub:

```asm
GetRIP proc
    lea rax, [here]
here:
    ret
GetRIP endp
```

Both approaches leak the instruction pointer to the caller in a completely normal-looking way, so this isn't an evasion improvement. What I wanted out of it was experimenting with an external asm stub and having something simpler to step through in WinDbg, since Fewer's `noinline` helper relies on the compiler not inlining `_ReturnAddress` and his source has comments fighting exactly that. The stub is one RIP-relative `lea`, which is the natural x64 idiom and easy to follow at the instruction level.

Once I have an address somewhere inside the DLL's mapped memory, I walk backwards byte by byte looking for the `MZ` signature. The search validates three things at each candidate: `IMAGE_DOS_SIGNATURE` (`0x5A4D`), a reasonable `e_lfanew` value (between `sizeof(IMAGE_DOS_HEADER)` and 1024), and the `IMAGE_NT_SIGNATURE` (`0x00004550`) at the offset `e_lfanew` points to. Matching all three by accident in unrelated memory is extremely unlikely.

### PEB walking with djb2 hashing

Fewer resolves `LoadLibraryA`, `GetProcAddress`, `VirtualAlloc`, and `NtFlushInstructionCache` by walking the PEB's `InMemoryOrderModuleList` and comparing export names as strings. I swapped the hash algorithm to djb2. The hashes themselves are precomputed by a small utility (`hash_generator.c`) and pasted into `CustomLoader.h` as constants, so the loader compares against literals at runtime.

Three hash functions handle the different contexts where names appear:

- `djb2_hash_unicode`: for module names read from the PEB's `BaseDllName` field (Unicode, normalised to uppercase).
- `djb2_hash_ascii` : for function names read from PE export tables. Export names are stored as ASCII byte strings and are treated case-sensitively during name resolution, so I preserve case in the hash.
- `djb2_hash_ascii_as_unicode` : for module names read from import descriptors (ASCII) that need to produce the same hash as their Unicode PEB equivalents.

The third function exists because import descriptors store module names as ASCII (e.g. `"KERNEL32.dll"`), but the PEB stores them as Unicode (e.g. `L"KERNEL32.DLL"`). Both need to produce the same hash so a single lookup table works across both sources. The function uppercases the ASCII input and hashes each byte as a DWORD, the same way the Unicode version does.

Resolution is factored into two reusable functions:

```c
ULONG_PTR ResolveModuleByHash(DWORD hash);
ULONG_PTR ResolveExportByHash(ULONG_PTR moduleBase, DWORD hash);
```

djb2 is well-known enough to appear in public detection signatures, with precomputed constants for common API names. Swapping it for a less common hash, or even keeping djb2 but with a different seed, would be a small but useful improvement.

### Indirect syscalls

Instead of calling `VirtualAlloc` or `NtAllocateVirtualMemory` directly, the loader extracts the syscall number and the address of the `syscall` instruction from the ntdll stub, then invokes the syscall via an assembly trampoline:

```asm
SetSyscallInfo proc
    lea rax, [syscallNumber]
    mov [rax], ecx
    lea rax, [syscallAddr]
    mov [rax], rdx
    ret
SetSyscallInfo endp

IndirectSyscall proc
    mov r10, rcx
    lea rax, [syscallNumber]
    mov eax, [rax]
    lea r11, [syscallAddr]
    jmp qword ptr [r11]
IndirectSyscall endp
```

The syscall number lives at offset `+4` of the ntdll stub (the `mov eax, <SSN>` instruction), and the `syscall` instruction itself is at offset `+0x12`. The trampoline `jmp`s directly to ntdll's `syscall` instruction, so RIP at the moment the syscall fires is inside ntdll, which is what kernel ETW events observe and is what makes this look normal at the kernel boundary. The return address on the stack still points back into our mapped image though, since the trampoline uses `jmp` and not `call`. Hiding that requires call stack spoofing, which is out of scope for this loader.

These offsets have been stable across the Windows builds I tested but they are technically build-dependent. A more production-ready loader would pattern-match the stub bytes (the `mov eax, imm32` opcode and the `syscall; ret` pair) instead of relying on fixed offsets. For a learning loader the fixed offsets are fine, but it's the kind of assumption that can break on a future Windows build with reordered or hot-patched stubs. Hooked stubs (from inline EDR hooks or hotpatching) also break this approach, since the bytes at `+4` and `+0x12` may be replaced with a jump to the EDR's instrumentation. Fetching syscall info from a clean ntdll mapping avoids this but is out of scope for this loader.

One detail to mention here: the `syscallNumber` and `syscallAddr` variables live in the `.code` section, not `.data`. The full explanation is in the bugs section near the end of the post; the short version is that running the loader from a raw DLL blob (before sections have been mapped) breaks RIP-relative references to `.data`, because `.data`'s file offset and virtual offset are different. Putting the variables in `.code`, right next to the assembly stub that uses them, avoids the problem.

The loader resolves three syscalls:

- `NtAllocateVirtualMemory` for memory allocation
- `NtProtectVirtualMemory` for section permission changes
- `NtFlushInstructionCache` for flushing the cache before executing mapped code

### Eliminating LoadLibraryA and GetProcAddress

Fewer's loader resolves `LoadLibraryA` and `GetProcAddress` from kernel32 and uses them for import resolution. Both are heavily hooked by EDRs. For modules already loaded in the process my loader goes directly to the PEB and parses the export table via `ResolveExportByHash`. No kernel32 touchpoints, no `GetProcAddress` calls.

For modules not already loaded the loader falls back to `LdrLoadDll`, resolved from ntdll the same way (hash-based export walk). `LdrLoadDll` sits one layer below `LoadLibraryA`, so going to it directly avoids the kernel32 dependency. Kernel32 and ntdll are loaded in every Win32 process, and user32 is loaded in most real applications, so the fallback path is rarely needed in practice. A minimal console process like the demo's `loader.exe` is one of the cases where it does fire, since user32 isn't pulled in by default.

The fallback path constructs a `UNICODE_STRING` on the stack from the ASCII module name in the import descriptor, since `LdrLoadDll` expects Unicode input. I used a small helper to do the ASCII-to-Unicode conversion without any CRT dependency.

## The loader: step by step

### Step 0: find our own base address

Call `GetRIP` to get an address inside the buffer containing our DLL. Walk backwards byte-by-byte, validating MZ + e_lfanew + PE signatures at each candidate.

The first screenshot shows the loader at the moment `CustomLoader` starts executing, before the backwards walk begins. RIP sits inside a private commit region with `PAGE_EXECUTE_READWRITE` protection and no module backing it, which is what the buffer that `loader.exe` allocated and copied the raw DLL bytes into looks like from the debugger's point of view. The first instruction is the linker's incremental thunk that jumps to the real function body.

![WinDbg showing RIP inside the raw DLL blob at the start of CustomLoader, before the backwards MZ walk begins](/assets/images/posts/reflective-dll-loader/step0-a-rip-in-raw-blob.png)

The second screenshot is from a later moment, after the backwards walk has stepped through some bytes and reached a candidate where `e_magic == 0x5A4D`. Three views of the same fact: the disassembly shows the `cmp eax, 5A4Dh` instruction that just executed, the register window confirms `RAX = 5A4D`, and the decoded `_IMAGE_DOS_HEADER` at `[rsp+50h]` (the local holding the candidate base) shows `e_magic : 0x5a4d`.

This particular candidate matches the MZ check but the surrounding fields (`e_cblp`, `e_cparhdr`, etc.) are clearly garbage, which is exactly the false-positive case the next two checks are designed to reject. The walk continues until a candidate passes all three: `MZ` signature, sane `e_lfanew`, and a valid `PE` signature at
`base + e_lfanew`.

![WinDbg showing the MZ signature check succeeding on a candidate address during the backwards walk](/assets/images/posts/reflective-dll-loader/step0-b-mz-check-succeeds.png)

### Step 1: resolve needed functions

Before the loader can do any real work it needs to call into ntdll but it hasn't yet resolved any imports or even located ntdll's base. Step 1 fixes that by walking the PEB.

`ResolveModuleByHash(NTDLLDLL_HASH)` walks `PEB->Ldr->InMemoryOrderModuleList`, hashes each `BaseDllName` with `djb2_hash_unicode`, and returns the base address of the entry whose hash matches. From there, `ResolveExportByHash(ntdllBase, <hash>)` parses ntdll's export directory and returns the address of each function the loader needs:

- `NtAllocateVirtualMemory` — for the new image allocation in Step 2
- `NtProtectVirtualMemory` — for the per section permission changes in Step 5b
- `NtFlushInstructionCache` — for the cache flush in Step 6
- `LdrLoadDll` — fallback for modules not already loaded, used in Step 4

For the three `Nt*` functions, the loader doesn't actually want to call their entry points directly. It wants the bytes of the ntdll stub so it can extract two things: the syscall number and the address of the `syscall` instruction.

```asm
4c 8b d1                ; mov r10, rcx
b8 18 00 00 00          ; mov eax, 18h     ← +4: SSN
f6 04 25 08 03 fe 7f 01 ; test ...
75 03                   ; jne ...
0f 05                   ; syscall          ← +0x12
c3                      ; ret
```

The syscall number lives at `stub + 4` (the immediate operand of `mov eax`) and the `syscall` instruction lives at `stub + 0x12`. The loader reads both into the variables the assembly trampoline uses (`syscallNumber` and `syscallAddr`) via `SetSyscallInfo`, and from that point on the syscall is issued via `IndirectSyscall` instead of by calling the stub directly.

![WinDbg showing the extraction of syscall number and syscall instruction address from an ntdll stub](/assets/images/posts/reflective-dll-loader/step1-syscall-extraction.png)

### Step 2: allocate memory and copy headers

Read `SizeOfImage` from the Optional Header. Allocate that much memory via indirect syscall to `NtAllocateVirtualMemory` with `PAGE_READWRITE`. Copy the PE headers byte-by-byte from the raw blob into the new allocation.

### Step 3: map sections

Walk the section header table. For each section, copy `SizeOfRawData` bytes from `PointerToRawData` (in the raw blob) to `VirtualAddress` (in the new allocation). This converts the image from disk layout (sections packed contiguously) to memory layout (sections aligned to `SectionAlignment`, usually `0x1000`). Sections with `VirtualSize > SizeOfRawData` (uninitialised data, e.g. `.bss`-style) don't need explicit zeroing because `NtAllocateVirtualMemory` hands back zeroed pages.

### Step 4: resolve imports

Walk the import descriptor table. For each imported module:

1. Read the module name from the descriptor's `Name` RVA.
2. Try the PEB first via hash lookup. If not found, fall back to `LdrLoadDll`.
3. Walk the two parallel thunk arrays: `OriginalFirstThunk` for import lookup information, `FirstThunk` for the IAT slots we patch.
4. For each import-by-name entry, hash the function name and resolve via `ResolveExportByHash`.
5. For each import-by-ordinal entry, index directly into `AddressOfFunctions` via `ResolveExportByOrdinal`.
6. Write the resolved address into the IAT slot.

#### Verifying the IAT was patched correctly

The most direct way to confirm Step 4 worked is to dump the patched IAT after `DllMain` is running, since by that point the import resolution must have succeeded for any of the payload's code to be callable.

Breaking at `user32!MessageBoxA` (which `DllMain` calls) gives a callstack with the return address into the mapped image:

![WinDbg callstack from a breakpoint on MessageBoxA showing the return address inside the mapped image](/assets/images/posts/reflective-dll-loader/step4a-callstack-from-messagebox.png)

The return address `0x0000024d9f707242` points into private memory with no module backing — that's the mapped image. Searching backwards for the `MZ` header returns two hits: the closer one (`0x0000024d9f700000`) is the mapped image, and the further one (`0x0000024d9f650000`) is the original raw blob the outer loader left in memory after copying it forward. The mapped image base is the one within range of the return address.

![WinDbg search for MZ header showing the mapped image base and the original raw blob base](/assets/images/posts/reflective-dll-loader/step4b-find-mapped-base.png)

`!dh` on the mapped image base decodes the PE headers. The data directories section gives the IAT's RVA and size:

![WinDbg !dh output showing PE data directories including the IAT RVA and size](/assets/images/posts/reflective-dll-loader/step4c-pe-headers-iat-rva.png)

Dumping that range with `dps` (display pointers with symbols) prints each IAT slot with its resolved function name:

![WinDbg dps dump of the IAT showing all slots resolved to real kernel32 and ntdll functions](/assets/images/posts/reflective-dll-loader/step4d-iat-resolved.png)

Every slot resolves to a real function. A few patterns worth noting:

- The bulk of the entries are `KERNEL32!*` functions, resolved via the fast PEB-walking path since kernel32 is preloaded.
- Many show as `KERNEL32!*Stub` (e.g. `QueryPerformanceCounterStub`, `IsValidCodePageStub`). These are kernel32 forwarders that ultimately point into kernelbase. The forwarder-resolution code in Step 4 handled these correctly, recursively resolving them through to their real implementations.
- A handful are `ntdll!*` directly. The loader walks ntdll's exports the same way it walks kernel32's, so direct resolution from any module works.

Further down the IAT, surrounded by zeros, `USER32!MessageBoxA` is the only user32 import and it resolved through the `LdrLoadDll` fallback path, since user32 wasn't loaded into the process when the loader started:

![WinDbg showing USER32!MessageBoxA resolved in the IAT via the LdrLoadDll fallback path](/assets/images/posts/reflective-dll-loader/step4e-iat-user32-fallback.png)

#### Forwarded exports

A problem I hit during testing was that several kernel32 exports my DLL imported were "resolving" to addresses inside kernel32's data region rather than code. The IAT entries pointed into readable memory but the bytes there weren't instructions, they were ASCII strings. Calling through them crashed.

The cause was forwarded exports. Many kernel32 functions (`QueryPerformanceCounter`, `EncodePointer`, `DecodePointer`, and others) are actually forwarded to kernelbase. When `AddressOfFunctions[ordinal]` contains an RVA that points inside the export directory itself, that RVA is not a code address but an ASCII string of the form `"KERNELBASE.QueryPerformanceCounter"` that tells the loader where the real function lives.

The fix:

1. After looking up the function RVA, check whether it falls within the export directory's range (`[exportDirRVA, exportDirRVA + exportDirSize)`).
2. If it does, parse the forwarder string: split on `.`, treat the left side as the target module name, the right side as either a function name or, if it starts with `#`, an ordinal.
3. Resolve the target module from the PEB (append `.DLL` to match the PEB's naming).
4. Recursively call `ResolveExportByHash` or `ResolveExportByOrdinal` on the target.

This handles classic forwarders. Modern Windows additionally routes many imports through the API Set Schema (the `api-ms-win-*` virtual DLL layer), which is a separate translation step this loader does not currently implement. A forwarder that ultimately points at an API Set entry will fail to resolve. In practice this hasn't been a problem with the small payload DLLs I've tested, but it's on the limitations list at the end.

### Step 5: apply base relocations

Compute the delta between the actual allocation base and the preferred `ImageBase` from the Optional Header. Walk the base relocation table, and for each `IMAGE_REL_BASED_DIR64` entry, add the delta to the 8-byte value at the target address.

Relocations are necessary because the compiler emits absolute addresses computed against the preferred `ImageBase` (typically `0x180000000` for x64 DLLs) for things like global variable references, function pointer tables, and jump tables. If the DLL ends up at a different base, those baked-in addresses point into nothing useful and need fixing up.

### Step 5b: apply per-section memory permissions

Walk the section headers again and set appropriate protection for each section via indirect syscall to `NtProtectVirtualMemory`. Protection is derived from `IMAGE_SECTION_HEADER.Characteristics`. The `IMAGE_SCN_MEM_EXECUTE`, `IMAGE_SCN_MEM_READ`, and `IMAGE_SCN_MEM_WRITE` bits map to the standard `PAGE_*` constants in the obvious way (a small `SectionProtection` helper in the loader does the conversion). Headers get dropped to `PAGE_READONLY` separately after the section loop.

A name-based lookup (`.text` to `PAGE_EXECUTE_READ`, `.rdata` to `PAGE_READONLY`, etc.) would also work for a payload like the demo's, since it only contains the standard MSVC sections. The Characteristics-based version costs barely any extra code and works correctly for binaries with non-standard section names too, which is why I went with it.

The initial allocation is `PAGE_READWRITE` so Steps 2-5 can write freely. Tightening permissions before any code in the mapped image runs avoids the RWX allocation pattern that most EDRs flag.

![WinDbg showing per-section memory permissions after NtProtectVirtualMemory calls](/assets/images/posts/reflective-dll-loader/step5b-permissions-after.png)

All five outputs share the same `AllocationBase` and the same `AllocationProtect: PAGE_READWRITE` because that's the original RW allocation. What changed is each region's current Protect, which now varies per section.

### Step 6: flush and call DllMain

Flush the instruction cache via indirect syscall to `NtFlushInstructionCache`, then call the DLL's entry point (`AddressOfEntryPoint` from the Optional Header) with `DLL_PROCESS_ATTACH`.

## The outer loader

Everything above describes what happens inside the payload DLL once execution jumps into `CustomLoader`. The outer loader is the program that gets execution to that point. It does almost nothing by comparison.

For the demo, the outer loader is a console program (`loader.exe`) that:

1. Reads the payload DLL from the path passed on the command line.
2. Allocates a read-write buffer and copies the file's bytes in verbatim.
3. Parses the in-memory DLL's export table to find the file offset of `CustomLoader`.
4. Marks the buffer executable.
5. Spawns a thread whose start address is `buffer_base + CustomLoader_offset`.

The only non-trivial part is step 3. The buffer holds the DLL in *disk layout* (sections packed contiguously starting at `PointerToRawData`), not *virtual layout* (sections aligned to `SectionAlignment` at `VirtualAddress`). Every RVA read from the PE inside the buffer has to be converted to a file offset before it's dereferenced, otherwise the pointer lands on unrelated bytes.

The conversion is to find the section whose `[VirtualAddress, VirtualAddress + SizeOfRawData)` range contains the RVA, then compute `rva - VirtualAddress + PointerToRawData`. It applies to every RVA the outer loader touches: the export directory RVA, the `AddressOfNames` array, each name string RVA, and the final function RVA.

`Rva2Offset` and `GetReflectiveLoaderOffset` are the two helpers doing this work and are copied from Stephen Fewer's `reflective_dll_injection` project. I kept them as-is because they do exactly what I needed and rewriting them wasn't the goal of this exercise.

It's worth pointing out the division of labour: the outer loader parses the PE only enough to find one export by name. The reflective loader inside the DLL does everything else: it maps every section, resolves every import, applies every relocation, and sets permissions on every section. This is the core of the RDI pattern. Most of the complexity is in the inner loader, because the inner loader is the one running inside the target process and that is where evasion matters.

## Running the demo

Build with `build.bat` from an x64 Native Tools Command Prompt for Visual Studio. This produces `loader.exe` and `payload.dll` in the project directory.

Run it:

```
loader.exe payload.dll
```

What you see:

```
[+] Opening payload.dll
[+] File is 672768 bytes
[+] Allocated buffer at 0000024D9F650000
[+] Copied file into buffer
[+] Located CustomLoader at file offset: 0x1FBC
[+] Marked buffer executable
[+] Spawning thread at 0000024D9F651FBC
```

A message box pops up with the text the payload's `DllMain` passes to `MessageBoxA`. The thread address in the last print is `buffer_base + loader_offset`, which confirms the outer loader found the right entry point.

![MessageBox popup from the demo payload DLL after successful reflective loading](/assets/images/posts/reflective-dll-loader/MessageBox.png)

`MessageBoxA` turned out to be a useful testing payload for this demo because it exercises both code paths in the loader's module resolution. `MessageBoxA` lives in `user32.dll`, which is not loaded by default in a minimal console process. `loader.exe` is one of those, so the loader's PEB walk for `user32` fails and falls back to the `LdrLoadDll` path. At the same time, the payload's IAT also has kernel32 imports (the linker pulls these in for any DLL by default), and kernel32 is preloaded in every Windows process, so those resolve through the fast PEB-walking path. One payload happens to cover both resolution paths.

Obviously, the demo is not operational tradecraft. It reads the payload from disk as a command-line argument because that keeps the walkthrough focused on the reflective loading mechanism. An operator in a real scenario would embed (and probably encrypt) the DLL bytes inside the loader binary so only one file lands on the target, rather than shipping a loader that needs a second file next to it. Delivery, staging, and evasion at the outer-loader level are separate topics.

`DllMain` calling `MessageBoxA` is a stand-in. In a real engagement, `DllMain` is typically a shellcode runner that stages additional payload code (often a beacon for a C2 framework) into executable memory and transfers control to it. Modern operators usually avoid the obvious large RWX region by staging through smaller per-page protections or other patterns, but the broad shape is the same. The reflective loader doesn't care what `DllMain` contains, its contract is just that `DllMain` gets called with `DLL_PROCESS_ATTACH` and a fully-resolved IAT. The message box here is a visible stand-in for "arbitrary code now runs with imports resolved."

## Bugs I hit in WinDbg

Most of the development time was spent tracing the loader instruction-by-instruction in WinDbg. The more instructive bugs:

**Global variables in `.data` break position independence when running from a raw blob.** My first version stored the syscall numbers in C global variables. The compiler emitted RIP-relative references to `.data`, but `.data`'s position in the raw DLL blob is different from its position in the mapped image. When the loader ran from the raw blob, the RIP-relative offset pointed into the wrong bytes and every syscall-number read produced garbage. The fix was making the variables local to `CustomLoader()` and, for the assembly stub, moving its storage into `.code`.

**Stack cookies / `__security_check_cookie` fail the same way.** Compiler-generated stack-cookie prologue/epilogue reads the cookie from `__security_cookie`, a global in `.data`. Same problem as above: the RIP-relative offset is computed against the cookie's *virtual* position but evaluated against its *raw file* position, so the prologue read lands on unrelated bytes and the epilogue's integrity check fails. `__security_check_cookie` (which is statically linked, not imported, so there's no IAT angle here) terminates the process. Compiling with `/GS-` disables cookie instrumentation in the DLL entirely.

I tested this while writing this post: building the demo without `/GS-` produces a loader that dies silently somewhere inside `CustomLoader` before any of the inner loader's work completes, so no message box, no progress, nothing. With `/GS-` back in, the demo runs cleanly end to end. MSVC's `/GS` heuristic only instruments functions whose stack layout matches specific patterns (arrays, `alloca`, certain struct shapes), so a loader written carefully enough *might* avoid it, but that breaks easily, a single edit adding a `char buf[N]` is enough. `/GS-` is the proper fix.

**CRT functions crash before imports are resolved.** CRT functions like `printf`, `sprintf`, and `OutputDebugStringA` all go through the IAT. When running from a raw blob whose IAT hasn't been patched, any CRT or Win32 API call crashes. Debug output during the loader itself has to come from WinDbg breakpoints and register/memory inspection, not runtime prints.

**Forwarded exports fail silently.** The IAT gets patched with a "valid" address (it's inside kernel32), but the bytes at that address are a forwarder string, not instructions. The crash only happens later when something calls through that IAT slot. Dumping the patched IAT with `dps` and checking that every entry resolves to a known function symbol catches this immediately.

## Detection surface

A loader that runs with no disk artefact and no `LoadLibrary` isn't invisible. Things an observer can potentially see:

| Artefact | Where | Notes |
| --- | --- | --- |
| `NtAllocateVirtualMemory` call from an unusual source module | Kernel ETW provider, EDR user-mode hooks if bypassed only via indirect syscall | The syscall still executes, stack trace shows the originating module. Call stack spoofing is out of scope for this loader. |
| Large RX/RWX region in a process that doesn't normally create one | Memory scan / page enumeration | Initial allocation is RW, re-protected per-section after mapping, no single RWX region, but the pattern of "new private commit, RW, partial RX" is still visible. |
| Private-committed memory with PE-like bytes at the start | Memory scan for MZ/PE signatures in non-image regions | `SizeOfHeaders` bytes at the start of the allocation match the raw DLL. Erasing the headers post-load is a common next step. |
| ntdll stub prologue bytes + `syscall` at `+0x12` | Return-address validation | RIP at syscall time is inside ntdll, which looks normal, but the return address on the stack still points into our mapped image. A user-mode hook or stack walk after the syscall will see the unusual caller. The `+0x12` jump into the syscall instruction is itself a recognizable pattern, since it bypasses the standard ntdll stub prologue entirely. |
| djb2 hashes in `.rdata` | Signature matching on known hash values | The precomputed constants in `CustomLoader.h` are djb2 of well-known API names. Public rules would match on these. |

None of these are unique to my implementation, they apply to any reflective loader of this shape. Fixing them is separate work.

## Current limitations

This is a learning loader, not a full replacement for the Windows loader. Things it does not implement:

- **TLS callbacks**. The TLS directory is not walked. Any DLL that depends on TLS callbacks for per-thread initialisation may run with uninitialised state or crash before reaching `DllMain`.
- **API Set Schema resolution**. Forwarders that route through the `api-ms-win-*` virtual DLL layer are not translated, so an import that ultimately points at an API Set entry will fail to resolve.
- **x64 unwind metadata**. `RtlAddFunctionTable` is not called on the mapped image's exception directory, so any C++ exceptions or structured exception unwinding will misbehave in code that needs them.
- **Loader-list registration**. The mapped image is not inserted into `PEB_LDR_DATA`, so APIs that enumerate loaded modules (and any tooling that walks them) will not see it.
- **Bound and delay-load imports**. Only the standard import directory is processed. The bound import table and the delay-load directory are ignored.

Most payload DLLs run fine without any of these, especially the small `DllMain` runners typical in red team work, which is why I haven't worked on them yet. Wider compatibility would need them implemented.
