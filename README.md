# elf-triage

A small, dependency-free static triage tool for Linux ELF binaries. Point it at
a sample you don't trust and it pulls the things you look at in the first few
minutes, without running it:

- the header — class (32/64), endianness, type, machine
- needed libraries, and the imported libc/syscall wrappers that matter
  (`execve`, `ptrace`, `dlopen`, `socket`/`connect`, `mprotect`, `memfd_create`, ...)
- writable+executable (RWX) segments and high-entropy sections (packed / encrypted)
- a UPX packer marker
- embedded URLs, IPs and suspicious paths worth pivoting on

Everything is static. The file is only ever opened read-only and parsed with
`struct` — nothing is executed — so it's safe to run against malware.

## Why

The first few minutes on an unknown Linux sample are always the same checklist:
`readelf -h` to see what it is, `readelf -d` for the needed libs,
`readelf --dyn-syms` for the imports, `strings | grep` for URLs and paths, and
an entropy check to see if it's packed. I got tired of running the same handful
of commands and eyeballing the output, so this does that first pass and prints
one short report. It's not a replacement for Ghidra / radare2 — it's the thing I
run *before* deciding whether a sample is worth opening in them.

## Usage

```bash
python3 elf_triage.py suspicious.elf
```

JSON output (handy for feeding into other tooling or a notebook):

```bash
python3 elf_triage.py suspicious.elf --json > report.json
```

Requires Python 3.8+. No third-party packages.

## Example

Run against a small crafted test fixture (the indicators in it are synthetic —
RFC 5737 documentation IPs and `example.com`):

```
================================================================
elf-triage report: sample.elf
================================================================
MD5    : 78c6fbe18f40d06faa58da037fdfad49
SHA256 : 93c8ee58128c11f1995fe5c77cfae41b97795b355110a62cdeb49b29f7d41b9e
Format : ELF64 / little-endian / EXEC / x86-64
Entry  : 0x401000
Risk   : HIGH (score 41)

[ Reasons ]  6
  - 9 high-signal import(s): execve, socket, connect, ptrace, dlopen, mprotect...
  - writable+executable LOAD segment (vaddr 0x600000)
  - high-entropy section .text (7.91 bits/byte)
  - RPATH/RUNPATH set: /tmp/.cache/.sysd
  - 6 suspicious path string(s)
  - 2 embedded IP(s)

[ Needed libraries ]  1
  - libc.so.6
  ! RPATH/RUNPATH /tmp/.cache/.sysd

[ High-signal imports ]  9
  ! execve           replaces the process image (exec)
  ! socket           opens a socket (network I/O)
  ! connect          outbound connection (possible C2)
  ! ptrace           anti-debugging or process injection (ptrace)
  ! dlopen           loads a shared object at runtime (dlopen)
  ! mprotect         changes page protection (self-modifying / unpacking)
  ! prctl            process control (anti-debug / name hiding)
  ! setuid           changes user id (privilege change)
  ! memfd_create     anonymous in-memory file (fileless execution)
  (dynamic symbol table: 11 imported)

[ RWX segments ]  1
  ! LOAD  vaddr 0x600000     filesz 48       (rwx)

[ High-entropy sections ]  1
  ! .text            7.91 bits/byte  (size 2048)

[ Packer markers ]  0

[ Embedded URLs ]  2
  - http://203.0.113.47/gate/checkin.php
  - https://cdn.example.com/u/beacon

[ Embedded IPs ]  2
  - 198.51.100.9
  - 203.0.113.47

[ Suspicious paths ]  6
  - /dev/shm/.x11-unix/Xv
  - /etc/cron.d/.apache-cache
  - /proc/self/status
  - /root/.ssh/authorized_keys
  - /tmp/.cache/.sysd
  - LD_PRELOAD=/tmp/.cache/libauth.so
================================================================
```

## How it works

- **Header / sections / segments** are parsed straight out of the file with
  `struct`. Both ELF32 and ELF64, little- and big-endian, are handled (the 32-bit
  program header puts `p_flags` in a different place, which is an easy thing to
  get wrong).
- **Imports** are the `.dynsym` entries that are undefined (`SHN_UNDEF`) — the
  functions the binary pulls in from shared libraries. The watchlist in
  `elf_triage.py` is a `name -> why` dict; add a line to extend it. Matching on
  the symbol name is exact, not a string-scan guess.
- **Needed libraries** and **RPATH/RUNPATH** come from `.dynamic`.
- **Entropy** is Shannon entropy per section; anything sizable above ~7.2
  bits/byte is flagged as likely packed or encrypted. A UPX stub is called out
  separately.
- **URLs / IPs / paths** are pulled from the printable strings across the whole
  file.

The URLs and IPs it surfaces are the starting point for the network side — I run
the same indicators against captures with
[pcap-ioc](https://github.com/audna-droid/pcap-ioc). Longer teardowns of individual
samples live in [re-notes](https://github.com/audna-droid/re-notes).

The risk score is deliberately dumb — a weighted count of the flagged items.
It's a sort order, not a verdict. Read the report.

## Notes / limitations

- String- and import-level matching means anything hidden behind `dlopen`/`dlsym`,
  or buried in a packed / obfuscated binary, won't show its real behaviour until
  it's unpacked. A clean report is not a clean sample.
- It trusts the section headers. A binary with stripped or deliberately
  corrupted section headers gives a thinner report — treat a missing dynamic
  symbol table on something that isn't statically linked as a signal in itself,
  and fall back to the segments and strings.
- It doesn't disassemble anything. Once triage says a sample is interesting,
  open it in a real tool.

## License

MIT
