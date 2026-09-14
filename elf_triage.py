#!/usr/bin/env python3
"""
elf-triage - quick static triage for suspicious Linux ELF binaries.

Parses an ELF the way the first few readelf / strings commands would: the
header, the section table, the dynamic symbol imports and needed libraries,
the segment permissions, per-section entropy, and any embedded URLs / IPs /
paths. Nothing is ever executed - the file is only opened read-only and parsed
as bytes with struct - so it's safe to point at a sample you don't trust.

Usage:
    python3 elf_triage.py suspicious.elf
    python3 elf_triage.py suspicious.elf --json > report.json
"""

import argparse
import hashlib
import json
import math
import re
import struct
import sys
from collections import Counter

# Imported libc / syscall wrappers worth a second look on an unknown sample,
# with why they matter. These are matched against the *names* in the dynamic
# symbol table, so they are exact-name hits, not string-scan guesses.
SUSPICIOUS_IMPORTS = {
    "system":        "runs a shell command (system())",
    "popen":         "runs a command and reads its output",
    "execve":        "replaces the process image (exec)",
    "execv":         "process execution",
    "execvp":        "process execution (PATH search)",
    "execl":         "process execution",
    "execlp":        "process execution (PATH search)",
    "fork":          "spawns a child process",
    "vfork":         "spawns a child process",
    "clone":         "spawns a child process / thread",
    "daemon":        "detaches into the background (daemonises)",
    "ptrace":        "anti-debugging or process injection (ptrace)",
    "dlopen":        "loads a shared object at runtime (dlopen)",
    "dlsym":         "resolves symbols at runtime (paired with dlopen)",
    "mprotect":      "changes page protection (self-modifying / unpacking)",
    "mmap":          "maps memory (often paired with mprotect to unpack)",
    "memfd_create":  "anonymous in-memory file (fileless execution)",
    "prctl":         "process control (anti-debug / name hiding)",
    "socket":        "opens a socket (network I/O)",
    "connect":       "outbound connection (possible C2)",
    "bind":          "binds a socket (possible backdoor listener)",
    "listen":        "listens for connections (possible backdoor)",
    "accept":        "accepts connections (possible backdoor)",
    "gethostbyname": "DNS resolution for a callout",
    "getaddrinfo":   "DNS resolution for a callout",
    "inet_addr":     "builds a raw IPv4 address (hard-coded C2)",
    "inet_pton":     "parses a literal IP address (hard-coded C2)",
    "setuid":        "changes user id (privilege change)",
    "setgid":        "changes group id (privilege change)",
    "chmod":         "changes file permissions (dropper / persistence)",
    "unlink":        "deletes a file (self-delete / anti-forensics)",
    "syscall":       "raw syscall (bypasses libc hooks)",
}

# Substrings that make an embedded path interesting on a Linux sample: staging
# directories, persistence locations, and loader / credential tricks.
PATH_MARKERS = (
    "/tmp/", "/var/tmp/", "/dev/shm/",
    "/etc/cron", "crontab", "/etc/rc.local", "/etc/init.d/",
    "/etc/systemd/", ".service",
    "/etc/ld.so.preload", "LD_PRELOAD",
    ".ssh/authorized_keys", "/root/", ".bashrc", "/etc/profile",
    "/etc/passwd", "/etc/shadow", "/proc/self/",
)

# No leading \b on the URL pattern: strings often abut neighbouring bytes with
# no separator (e.g. "<junk>http://..."), and the scheme is distinctive enough.
PRINTABLE_RE = re.compile(rb"[\x20-\x7e]{4,}")
URL_RE = re.compile(r"(?:https?|ftp)://[^\s\"'<>|)\]]+")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

ELF_MAGIC = b"\x7fELF"
E_TYPE = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
E_MACHINE = {
    0x02: "SPARC", 0x03: "x86", 0x08: "MIPS", 0x14: "PowerPC",
    0x15: "PowerPC64", 0x16: "S390", 0x28: "ARM", 0x2a: "SuperH",
    0x32: "IA-64", 0x3e: "x86-64", 0xb7: "AArch64", 0xf3: "RISC-V",
}
SHT_NULL, SHT_DYNAMIC, SHT_NOBITS, SHT_DYNSYM = 0, 6, 8, 11
PT_LOAD = 1
PF_X, PF_W, PF_R = 1, 2, 4
DT_NULL, DT_NEEDED, DT_RPATH, DT_RUNPATH = 0, 1, 15, 29
SHN_UNDEF = 0
ENTROPY_FLAG = 7.2       # bits/byte; above this a sizable section looks packed
ENTROPY_MIN_SIZE = 256   # entropy is meaningless on tiny sections


class ElfError(Exception):
    """Raised when the bytes do not parse as a usable ELF."""


def shannon_entropy(data):
    """Bits per byte, 0.0 (uniform) .. 8.0 (random/compressed)."""
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


def _u(fmt, buf, off):
    try:
        return struct.unpack_from(fmt, buf, off)
    except struct.error as exc:
        raise ElfError(f"truncated structure at offset {off}") from exc


def _cstr(buf, off):
    if off < 0 or off >= len(buf):
        return ""
    end = buf.find(b"\x00", off)
    end = len(buf) if end < 0 else end
    return buf[off:end].decode("latin-1", "ignore")


def _section_bytes(data, sec):
    if sec["type"] in (SHT_NULL, SHT_NOBITS):
        return b""
    start, end = sec["offset"], sec["offset"] + sec["size"]
    if start < 0 or start > end or end > len(data):
        return b""
    return data[start:end]


def parse_elf(data):
    """Parse the ELF header, section table and program headers."""
    if len(data) < 16 or data[:4] != ELF_MAGIC:
        raise ElfError("not an ELF file (bad magic)")
    ei_class, ei_data = data[4], data[5]
    if ei_class not in (1, 2):
        raise ElfError(f"unknown EI_CLASS {ei_class}")
    if ei_data not in (1, 2):
        raise ElfError(f"unknown EI_DATA {ei_data}")
    is64 = ei_class == 2
    fmt = "<" if ei_data == 1 else ">"

    hdr_fmt = fmt + ("HHIQQQIHHHHHH" if is64 else "HHIIIIIHHHHHH")
    (e_type, e_machine, _ver, e_entry, e_phoff, e_shoff, _flags,
     _ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx) = _u(hdr_fmt, data, 16)

    sections = _parse_sections(data, fmt, is64, e_shoff, e_shentsize, e_shnum, e_shstrndx)
    segments = _parse_segments(data, fmt, is64, e_phoff, e_phentsize, e_phnum)

    return {
        "class": "ELF64" if is64 else "ELF32",
        "endianness": "little" if ei_data == 1 else "big",
        "is64": is64,
        "fmt": fmt,
        "type": E_TYPE.get(e_type, f"0x{e_type:x}"),
        "machine": E_MACHINE.get(e_machine, f"0x{e_machine:x}"),
        "entry": e_entry,
        "sections": sections,
        "segments": segments,
    }


def _parse_sections(data, fmt, is64, e_shoff, entsize, count, shstrndx):
    sections = []
    if not (e_shoff and count):
        return sections
    sh_fmt = fmt + ("IIQQQQIIQQ" if is64 else "IIIIIIIIII")
    for i in range(count):
        off = e_shoff + i * entsize
        if off + struct.calcsize(sh_fmt) > len(data):
            break  # bogus section count on a corrupt / truncated file
        (sh_name, sh_type, sh_flags, sh_addr, sh_offset,
         sh_size, sh_link, _info, _align, sh_entsize) = _u(sh_fmt, data, off)
        sections.append({
            "idx": i, "name_off": sh_name, "name": "", "type": sh_type,
            "flags": sh_flags, "addr": sh_addr, "offset": sh_offset,
            "size": sh_size, "link": sh_link, "entsize": sh_entsize,
        })
    # resolve section names from the section-header string table
    if sections and 0 <= shstrndx < len(sections):
        strtab = _section_bytes(data, sections[shstrndx])
        for sec in sections:
            sec["name"] = _cstr(strtab, sec["name_off"])
    return sections


def _parse_segments(data, fmt, is64, e_phoff, entsize, count):
    segments = []
    if not (e_phoff and count):
        return segments
    ph_fmt = fmt + ("IIQQQQQQ" if is64 else "IIIIIIII")
    size = struct.calcsize(ph_fmt)
    for i in range(count):
        off = e_phoff + i * entsize
        if off + size > len(data):
            break
        vals = _u(ph_fmt, data, off)
        if is64:
            p_type, p_flags, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, _align = vals
        else:  # 32-bit puts p_flags after p_memsz, not after p_type
            p_type, p_offset, p_vaddr, _paddr, p_filesz, p_memsz, p_flags, _align = vals
        segments.append({
            "type": p_type, "flags": p_flags, "offset": p_offset,
            "vaddr": p_vaddr, "filesz": p_filesz, "memsz": p_memsz,
        })
    return segments


def _linked_strtab(data, sections, sec):
    """The string table a section points at via sh_link, or .dynstr by name."""
    link = sec["link"]
    if 0 <= link < len(sections):
        blob = _section_bytes(data, sections[link])
        if blob:
            return blob
    for other in sections:
        if other["name"] == ".dynstr":
            return _section_bytes(data, other)
    return b""


def parse_dynsyms(data, elf):
    """Return (imported_names, total_dynsym_count) from .dynsym."""
    sections, is64, fmt = elf["sections"], elf["is64"], elf["fmt"]
    dynsym = next((s for s in sections if s["type"] == SHT_DYNSYM), None)
    if dynsym is None:
        dynsym = next((s for s in sections if s["name"] == ".dynsym"), None)
    if dynsym is None:
        return [], 0
    strtab = _linked_strtab(data, sections, dynsym)
    blob = _section_bytes(data, dynsym)
    entsize = dynsym["entsize"] or (24 if is64 else 16)
    sym_fmt = fmt + ("IBBHQQ" if is64 else "IIIBBH")
    size = struct.calcsize(sym_fmt)
    imports, total = [], 0
    for off in range(0, len(blob) - size + 1, entsize):
        vals = _u(sym_fmt, blob, off)
        if is64:
            st_name, _info, _other, st_shndx, _val, _sz = vals
        else:
            st_name, _val, _sz, _info, _other, st_shndx = vals
        if st_name == 0:
            continue
        total += 1
        name = _cstr(strtab, st_name)
        if name and st_shndx == SHN_UNDEF:
            imports.append(name)
    return imports, total


def parse_dynamic(data, elf):
    """Return (needed_libraries, rpath_runpath_entries) from .dynamic."""
    sections, is64, fmt = elf["sections"], elf["is64"], elf["fmt"]
    dyn = next((s for s in sections if s["type"] == SHT_DYNAMIC), None)
    if dyn is None:
        return [], []
    strtab = _linked_strtab(data, sections, dyn)
    blob = _section_bytes(data, dyn)
    ent_fmt = fmt + ("QQ" if is64 else "II")
    size = struct.calcsize(ent_fmt)
    needed, paths = [], []
    for off in range(0, len(blob) - size + 1, size):
        d_tag, d_val = _u(ent_fmt, blob, off)
        if d_tag == DT_NULL:
            break
        if d_tag == DT_NEEDED:
            needed.append(_cstr(strtab, d_val))
        elif d_tag in (DT_RPATH, DT_RUNPATH):
            paths.append(_cstr(strtab, d_val))
    return [n for n in needed if n], [p for p in paths if p]


def entropy_sections(data, elf):
    out = []
    for sec in elf["sections"]:
        if sec["size"] < ENTROPY_MIN_SIZE:
            continue
        blob = _section_bytes(data, sec)
        if not blob:
            continue
        name = sec["name"] or f"sec#{sec['idx']}"
        out.append((name, shannon_entropy(blob), sec["size"]))
    return out


def rwx_segments(elf):
    rwx = (PF_W | PF_X)
    return [s for s in elf["segments"]
            if s["type"] == PT_LOAD and (s["flags"] & rwx) == rwx]


def packer_markers(data, elf):
    marks = []
    if b"UPX!" in data:
        marks.append("UPX! signature")
    names = {s["name"] for s in elf["sections"]}
    if {"UPX0", "UPX1"} & names:
        marks.append("UPX section names (UPX0/UPX1)")
    return marks


def _valid_ip(ip):
    parts = ip.split(".")
    try:
        return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def _ip_key(ip):
    return tuple(int(o) for o in ip.split("."))


def extract_iocs(data):
    urls, ips, paths = set(), set(), set()
    for match in PRINTABLE_RE.finditer(data):
        s = match.group().decode("ascii", "ignore")
        for url in URL_RE.findall(s):
            urls.add(url.rstrip(".,);"))
        for ip in IP_RE.findall(s):
            if _valid_ip(ip):
                ips.add(ip)
        if any(marker in s for marker in PATH_MARKERS):
            paths.add(s.strip())
    return sorted(urls), sorted(ips, key=_ip_key), sorted(paths)


def flag_string(flags):
    return ("r" if flags & PF_R else "-") + \
           ("w" if flags & PF_W else "-") + \
           ("x" if flags & PF_X else "-")


def risk_label(score):
    if score >= 12:
        return "HIGH"
    if score >= 5:
        return "MEDIUM"
    return "LOW"


def triage(path):
    with open(path, "rb") as f:
        data = f.read()

    elf = parse_elf(data)
    imports, dynsym_total = parse_dynsyms(data, elf)
    needed, rpaths = parse_dynamic(data, elf)
    ent_all = entropy_sections(data, elf)
    rwx = rwx_segments(elf)
    packer = packer_markers(data, elf)
    urls, ips, paths = extract_iocs(data)

    seen = set()
    flagged_imports = []
    for name in imports:
        if name in SUSPICIOUS_IMPORTS and name not in seen:
            seen.add(name)
            flagged_imports.append({"name": name, "note": SUSPICIOUS_IMPORTS[name]})
    high_entropy = [{"section": n, "entropy": round(e, 2), "size": sz}
                    for (n, e, sz) in ent_all if e >= ENTROPY_FLAG]

    reasons = []
    if flagged_imports:
        shown = ", ".join(h["name"] for h in flagged_imports[:6])
        more = "..." if len(flagged_imports) > 6 else ""
        reasons.append(f"{len(flagged_imports)} high-signal import(s): {shown}{more}")
    for seg in rwx:
        reasons.append(f"writable+executable LOAD segment (vaddr 0x{seg['vaddr']:x})")
    for h in high_entropy:
        reasons.append(f"high-entropy section {h['section']} ({h['entropy']:.2f} bits/byte)")
    for mark in packer:
        reasons.append(f"packer marker: {mark}")
    for p in rpaths:
        reasons.append(f"RPATH/RUNPATH set: {p}")
    if paths:
        reasons.append(f"{len(paths)} suspicious path string(s)")
    if ips:
        reasons.append(f"{len(ips)} embedded IP(s)")

    score = (2 * len(flagged_imports) + 3 * len(rwx) + 2 * len(high_entropy)
             + (4 if packer else 0) + 2 * len(rpaths)
             + len(urls) + len(ips) + 2 * len(paths))

    return {
        "file": path,
        "md5": hashlib.md5(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "class": elf["class"],
        "endianness": elf["endianness"],
        "elf_type": elf["type"],
        "machine": elf["machine"],
        "entry": f"0x{elf['entry']:x}",
        "needed_libraries": needed,
        "rpath_runpath": rpaths,
        "dynamic_symbols_imported": dynsym_total,
        "high_signal_imports": flagged_imports,
        "rwx_segments": [{"vaddr": f"0x{s['vaddr']:x}", "filesz": s["filesz"],
                          "flags": flag_string(s["flags"])} for s in rwx],
        "high_entropy_sections": high_entropy,
        "packer_markers": packer,
        "urls": urls,
        "ips": ips,
        "suspicious_paths": paths,
        "reasons": reasons,
        "risk_score": score,
        "risk": risk_label(score),
    }


def _section(title, count):
    print(f"\n[ {title} ]  {count}")


def print_report(r):
    line = "=" * 64
    print(line)
    print(f"elf-triage report: {r['file']}")
    print(line)
    print(f"MD5    : {r['md5']}")
    print(f"SHA256 : {r['sha256']}")
    print(f"Format : {r['class']} / {r['endianness']}-endian / {r['elf_type']} / {r['machine']}")
    print(f"Entry  : {r['entry']}")
    print(f"Risk   : {r['risk']} (score {r['risk_score']})")

    _section("Reasons", len(r["reasons"]))
    for why in r["reasons"]:
        print(f"  - {why}")

    _section("Needed libraries", len(r["needed_libraries"]))
    for lib in r["needed_libraries"]:
        print(f"  - {lib}")
    for rp in r["rpath_runpath"]:
        print(f"  ! RPATH/RUNPATH {rp}")

    _section("High-signal imports", len(r["high_signal_imports"]))
    for hit in r["high_signal_imports"]:
        print(f"  ! {hit['name']:<16} {hit['note']}")
    if r["dynamic_symbols_imported"]:
        print(f"  (dynamic symbol table: {r['dynamic_symbols_imported']} imported)")

    _section("RWX segments", len(r["rwx_segments"]))
    for seg in r["rwx_segments"]:
        print(f"  ! LOAD  vaddr {seg['vaddr']:<12} filesz {seg['filesz']:<8} ({seg['flags']})")

    _section("High-entropy sections", len(r["high_entropy_sections"]))
    for h in r["high_entropy_sections"]:
        print(f"  ! {h['section']:<16} {h['entropy']:.2f} bits/byte  (size {h['size']})")

    _section("Packer markers", len(r["packer_markers"]))
    for mark in r["packer_markers"]:
        print(f"  ! {mark}")

    _section("Embedded URLs", len(r["urls"]))
    for u in r["urls"][:40]:
        print(f"  - {u}")
    if len(r["urls"]) > 40:
        print(f"  ... {len(r['urls']) - 40} more")

    _section("Embedded IPs", len(r["ips"]))
    for ip in r["ips"][:40]:
        print(f"  - {ip}")

    _section("Suspicious paths", len(r["suspicious_paths"]))
    for p in r["suspicious_paths"][:40]:
        print(f"  - {p[:100]}")
    print(line)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Static triage for suspicious Linux ELF binaries (never runs the sample).")
    ap.add_argument("elf", help="path to the ELF file")
    ap.add_argument("--json", action="store_true", help="emit a JSON report instead of text")
    args = ap.parse_args(argv)

    try:
        report = triage(args.elf)
    except FileNotFoundError:
        sys.exit(f"error: no such file: {args.elf}")
    except IsADirectoryError:
        sys.exit(f"error: not a file: {args.elf}")
    except ElfError as exc:
        sys.exit(f"error: {exc}")

    if args.json:
        json.dump(report, sys.stdout, indent=2)
        print()
    else:
        print_report(report)


if __name__ == "__main__":
    main()
