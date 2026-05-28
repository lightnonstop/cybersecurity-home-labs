# Volatility 3 Command Reference

## Standard Triage (run on every dump)
| Plugin | Command | What it shows |
|---|---|---|
| OS Info | `vol -f dump.raw windows.info` | OS version, kernel, architecture |
| Process List | `vol -f dump.raw windows.pslist` | All running processes flat list |
| Process Tree | `vol -f dump.raw windows.pstree` | Parent-child process hierarchy |
| Network Connections | `vol -f dump.raw windows.netscan` | All connections and sockets |
| Command Lines | `vol -f dump.raw windows.cmdline` | Full args for every process |
| DLL List | `vol -f dump.raw windows.dlllist` | DLLs per process |
| File Scan | `vol -f dump.raw windows.filescan` | Files open in memory |
| Malware Detection | `vol -f dump.raw windows.malware.malfind` | Injected executable regions |

## Targeted Investigation
| Plugin | Command | When to use |
|---|---|---|
| Filter by PID | `vol -f dump.raw windows.dlllist --pid 1234` | Investigate specific process |
| Dump a process | `vol -f dump.raw windows.dumpfiles --pid 1234` | Extract process executable |
| Handles | `vol -f dump.raw windows.handles --pid 1234` | Mutexes, files, registry keys |
| Registry hives | `vol -f dump.raw windows.registry.hivelist` | All loaded registry hives |
| MFT scan | `vol -f dump.raw windows.mftscan.MFTScan` | Master File Table entries |