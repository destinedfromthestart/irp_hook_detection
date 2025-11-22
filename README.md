# pride irp hook detection poc

kernel-mode rootkit & irp hook detection poc.
focuses on integrity checks for driver major functions and detecting dkom-based hiding techniques.

## features

**irp integrity**
- scans major function tables for all loaded drivers
- validates handlers reside within the legit driver module
- enforces .text section integrity (catches discardable section hijacks)
- resolves trampolines/thunks (e9, ff 25, mov+jmp) by disassembling the first 15 bytes of the handler
- validates cross-driver jumps (prevents hooking via legitimate vulnerable drivers unless they are core kernel modules)
---
**anti-rootkit**
- compares the official \driver directory against the \device object directory
- flags drivers that have unlinked themselves from the loaded module list (dkom) but still maintain active device objects

## detection vectors

1. **hooked irp**: handler points outside the driver's .text section
2. **inline trampoline**: handler starts with or includes a jump to allocated memory (shellcode)
3. **hidden driver**: driver object exists in device tree but is missing from directory service

## limitations

- **load order heuristic**: drivers loaded late in boot sequence (index >= 150) are flagged for suspicious cross-driver jumps. early core drivers get a pass to avoid false positives on legit ntoskrnl/hal wrappers. a cheat could bypass this by loading extremely early (requires cert) or manipulating its reported index via dkom.
- **.text patches**: this tool checks *where* the handler points, not the integrity of the code bytes themselves (checksum). inline hooks deep inside the function won't be flagged, only redirects at the function start.

## todo:

- implement full .text section hashing to detect patches that don't redirect control flow
- refine load-order heuristics to dynamically resolve dependency chains instead of fixed index thresholds
- fix the hidden driver detection as it currently flags filesystem objects since it only enumerates device->driver and not device->filesystem
- reduce false positive rate from low to extremely low / impossible for the irp hooks, as of testing it currently false-positives on 1-2 drivers at the maximum
  
## usage

- load the driver with dse bypass, like gdrvloader and check debugview/dbgview64 for logs.
