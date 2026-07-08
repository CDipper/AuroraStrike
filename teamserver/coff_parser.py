"""
AURORA C2 - COFF parser for BOF (Beacon Object File) inline execution.

Parses Windows PE/COFF object files (.o) and packages them into a binary blob
that the implant can load and execute inline.

Blob format (all integers little-endian):
    [4-byte int: entryPoint]       offset of entry function in .text
    [4-byte int: codeLen][code]    .text section
    [4-byte int: rdataLen][rdata]  .rdata section
    [4-byte int: dataLen][data]    .data section (includes .bss)
    [4-byte int: relocLen][relocs] Beacon relocation entries + func name strings
    [4-byte int: argsLen][args]    entry function arguments

BEACON_RELOCATION entry (12 bytes):
    [2-byte relocType]      COFF relocation type (4=REL32, 1=ADDR64, etc.)
    [2-byte secType]        Beacon category:
                              RDATA(1024) / DATA(1025) / EXE(1026)
                              DYNAMIC_FUNC(1027) / END(1028)
                              For DYNAMIC_FUNC, low byte = func index
    [4-byte rvaddre]        offset in source section
    [4-byte value]          target offset in target section, or
                            func-name string offset (for DYNAMIC_FUNC)

After all BEACON_RELOCATION entries (including END), the relocation buffer
contains null-terminated function name strings for DYNAMIC_FUNC entries.
The `value` field of a DYNAMIC_FUNC entry is the byte offset of the name
within that string area. The implant uses the name to resolve the function
address and the secType func index to locate the resolved pointer.
"""
from __future__ import annotations

import base64
import struct
from dataclasses import dataclass
from pathlib import Path

# ── Beacon relocation types ──────────────────────────────
RDATA_RELOC_TYPE = 1024
DATA_RELOC_TYPE = 1025
EXE_RELOC_TYPE = 1026
DYNAMIC_FUNC_RELOC_TYPE = 1027
END_RELOC_TYPE = 1028

# ── Source section indices (encoded in secType lower byte) ──
SEC_TEXT = 0
SEC_RDATA = 1
SEC_DATA = 2

# ── Beacon_Internal_Api function name → index mapping ──
# Index 0-30 are fixed slots in the struct (see api.h).
# Index 31+ map into dynamicFns[MAX_DYNAMIC_FUNCTIONS] (32 slots).
# The implant resolves index 0-30 from the pre-populated struct;
# indices 31+ are resolved on-the-fly via LoadLibraryA/GetProcAddress.
BEACON_INTERNAL_API_NAMES: list[str] = [
    "LoadLibraryA",                # 0
    "FreeLibrary",                 # 1
    "GetProcAddress",              # 2
    "GetModuleHandleA",            # 3
    "BeaconDataParse",             # 4
    "BeaconDataPtr",               # 5
    "BeaconDataInt",               # 6
    "BeaconDataShort",             # 7
    "BeaconDataLength",            # 8
    "BeaconDataExtract",           # 9
    "BeaconFormatAlloc",           # 10
    "BeaconFormatReset",           # 11
    "BeaconFormatPrintf",          # 12
    "BeaconFormatAppend",          # 13
    "BeaconFormatFree",            # 14
    "BeaconFormatToString",        # 15
    "BeaconFormatInt",             # 16
    "BeaconOutput",                # 17
    "BeaconPrintf",                # 18
    "BeaconErrorD",                # 19
    "BeaconErrorDD",               # 20
    "BeaconErrorNA",               # 21
    "BeaconUseToken",              # 22
    "BeaconIsAdmin",               # 23
    "BeaconRevertToken",           # 24
    "BeaconGetSpawnTo",            # 25
    "BeaconCleanupProcess",        # 26
    "BeaconInjectProcess",         # 27
    "BeaconSpawnTemporaryProcess", # 28
    "BeaconInjectTemporaryProcess",# 29
    "toWideChar",                  # 30
]

BEACON_INTERNAL_API_MAP: dict[str, int] = {
    name: idx for idx, name in enumerate(BEACON_INTERNAL_API_NAMES)
}
DYNAMIC_FUNC_BASE = len(BEACON_INTERNAL_API_NAMES)  # 31 — first dynamicFns slot
MAX_DYNAMIC_FUNCTIONS = 32

# ── COFF constants ───────────────────────────────────────
IMAGE_FILE_MACHINE_AMD64 = 0x8664

IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

IMAGE_SYM_UNDEFINED = 0
IMAGE_SYM_ABSOLUTE = -1
IMAGE_SYM_DEBUG = -2

# x64 relocation types
IMAGE_REL_AMD64_ADDR64 = 0x0001
IMAGE_REL_AMD64_ADDR32NB = 0x0002
IMAGE_REL_AMD64_REL32 = 0x0004
IMAGE_REL_AMD64_REL32_1 = 0x0005
IMAGE_REL_AMD64_REL32_2 = 0x0006
IMAGE_REL_AMD64_REL32_3 = 0x0007
IMAGE_REL_AMD64_REL32_4 = 0x0008
IMAGE_REL_AMD64_REL32_5 = 0x0009

# Struct sizes
COFF_HEADER_SIZE = 20
SECTION_HEADER_SIZE = 40
SYMBOL_SIZE = 18
RELOCATION_SIZE = 10

RELOC_STRUCT_FMT = "<hhiI"  # relocType (COFF reloc type), secType (Beacon category), rvaddre, value
RELOC_STRUCT_SIZE = struct.calcsize(RELOC_STRUCT_FMT)


# ── Exceptions ──────────────────────────────────────────

class CoffParseError(Exception):
    pass


# ── Data classes ────────────────────────────────────────

@dataclass
class CoffSection:
    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_data_offset: int
    reloc_offset: int
    num_relocations: int
    characteristics: int
    section_index: int  # 1-based


@dataclass
class CoffSymbol:
    name: str
    value: int
    section_number: int  # signed: >0 = section index, 0 = undefined, -1 = abs, -2 = debug
    type: int
    storage_class: int
    num_aux_symbols: int
    symbol_index: int


@dataclass
class CoffRelocation:
    virtual_address: int
    symbol_table_index: int
    reloc_type: int


@dataclass
class ParsedCoff:
    machine: int
    sections: list[CoffSection]
    symbols: list[CoffSymbol]
    symbol_map: dict  # raw_index → CoffSymbol (includes aux symbols as slots)
    string_table: bytes
    raw_data: bytes


# ── COFF parsing ────────────────────────────────────────

def parse_coff(data: bytes) -> ParsedCoff:
    if len(data) < COFF_HEADER_SIZE:
        raise CoffParseError("File too small to be a valid COFF object")

    machine, num_sections, _ts, ptr_symtab, num_symbols, \
        size_opt_hdr, _chars = struct.unpack_from("<HHIIIHH", data, 0)

    if machine != IMAGE_FILE_MACHINE_AMD64:
        raise CoffParseError(f"Only x64 COFF/BOF is supported (machine=0x{machine:04X})")

    # Parse string table (starts right after symbol table)
    str_table_offset = ptr_symtab + num_symbols * SYMBOL_SIZE if ptr_symtab > 0 else 0
    string_table = b""
    if str_table_offset > 0 and str_table_offset + 4 <= len(data):
        str_table_size = struct.unpack_from("<I", data, str_table_offset)[0]
        str_end = str_table_offset + str_table_size
        if str_end > len(data):
            str_end = len(data)
        string_table = data[str_table_offset:str_end]

    # Parse section headers
    offset = COFF_HEADER_SIZE + size_opt_hdr
    sections: list[CoffSection] = []
    for i in range(num_sections):
        if offset + SECTION_HEADER_SIZE > len(data):
            raise CoffParseError("Section header truncated")

        raw_name = data[offset:offset + 8]
        vsize, vaddr, raw_sz, raw_off, reloc_off, _ln_off, \
            num_relocs, _num_ln, sect_chars = struct.unpack_from(
                "<IIIIIIHHI", data, offset + 8)

        name = _decode_name(raw_name, string_table)
        sections.append(CoffSection(
            name=name,
            virtual_size=vsize,
            virtual_address=vaddr,
            raw_size=raw_sz,
            raw_data_offset=raw_off,
            reloc_offset=reloc_off,
            num_relocations=num_relocs,
            characteristics=sect_chars,
            section_index=i + 1,
        ))
        offset += SECTION_HEADER_SIZE

    # Parse symbol table
    symbols: list[CoffSymbol] = []
    symbol_map: dict[int, CoffSymbol] = {}  # raw_index → CoffSymbol
    if ptr_symtab > 0 and num_symbols > 0:
        sym_off = ptr_symtab
        i = 0
        while i < num_symbols:
            if sym_off + SYMBOL_SIZE > len(data):
                break
            raw_name = data[sym_off:sym_off + 8]
            value, sec_num, sym_type, storage_cls, num_aux = \
                struct.unpack_from("<IhHBB", data, sym_off + 8)
            name = _decode_symbol_name(raw_name, string_table)
            sym = CoffSymbol(
                name=name,
                value=value,
                section_number=sec_num,
                type=sym_type,
                storage_class=storage_cls,
                num_aux_symbols=num_aux,
                symbol_index=i,
            )
            symbols.append(sym)
            symbol_map[i] = sym  # primary symbol
            # Also map aux symbol slots so reloc lookups don't miss
            for aux_i in range(1, num_aux + 1):
                symbol_map[i + aux_i] = sym
            step = 1 + num_aux
            sym_off += SYMBOL_SIZE * step
            i += step

    return ParsedCoff(
        machine=machine,
        sections=sections,
        symbols=symbols,
        symbol_map=symbol_map,
        string_table=string_table,
        raw_data=data,
    )


def _decode_name(raw: bytes, string_table: bytes) -> str:
    """Decode a COFF section name (8 bytes, may reference string table)."""
    if raw[0:1] == b"/":
        digits = raw[1:].split(b"\x00")[0]
        if digits.isdigit():
            off = int(digits)
            if 0 < off < len(string_table):
                end = string_table.find(b"\x00", off)
                if end == -1:
                    end = len(string_table)
                return string_table[off:end].decode("ascii", errors="replace")
    return raw.split(b"\x00")[0].decode("ascii", errors="replace")


def _decode_symbol_name(raw: bytes, string_table: bytes) -> str:
    """Decode a COFF symbol name (8 bytes; first 4 zero => next 4 = str offset)."""
    if raw[:4] == b"\x00\x00\x00\x00":
        off = struct.unpack_from("<I", raw, 4)[0]
        if 0 < off < len(string_table):
            end = string_table.find(b"\x00", off)
            if end == -1:
                end = len(string_table)
            return string_table[off:end].decode("ascii", errors="replace")
        return ""
    return raw.split(b"\x00")[0].decode("ascii", errors="replace")


def _read_relocations(coff: ParsedCoff, section: CoffSection) -> list[CoffRelocation]:
    if section.num_relocations == 0 or section.reloc_offset == 0:
        return []
    out: list[CoffRelocation] = []
    off = section.reloc_offset
    for _ in range(section.num_relocations):
        if off + RELOCATION_SIZE > len(coff.raw_data):
            break
        va, sym_idx, rtype = struct.unpack_from("<IIH", coff.raw_data, off)
        out.append(CoffRelocation(va, sym_idx, rtype))
        off += RELOCATION_SIZE
    return out


# ── Section classification ──────────────────────────────

def _classify_section(section: CoffSection) -> str:
    """Return 'text', 'rdata', 'data', 'bss', or 'other'."""
    name = section.name.lower()
    chars = section.characteristics

    if name.startswith(".text") or name.startswith("text"):
        return "text"
    if name.startswith(".rdata") or name.startswith("rdata"):
        return "rdata"
    if name.startswith(".bss") or name.startswith("bss"):
        return "bss"
    if name.startswith(".data") or name.startswith("data"):
        return "data"

    if chars & IMAGE_SCN_MEM_EXECUTE:
        return "text"
    if chars & IMAGE_SCN_CNT_UNINITIALIZED_DATA:
        return "bss"
    if chars & IMAGE_SCN_CNT_INITIALIZED_DATA:
        return "data" if (chars & IMAGE_SCN_MEM_WRITE) else "rdata"
    return "other"


def _section_raw_data(coff: ParsedCoff, section: CoffSection, stype: str) -> bytes:
    if stype == "bss":
        return b"\x00" * max(section.virtual_size, 0)
    if section.raw_size == 0 or section.raw_data_offset == 0:
        return b""
    end = min(section.raw_data_offset + section.raw_size, len(coff.raw_data))
    return coff.raw_data[section.raw_data_offset:end]


# ── Entry point ─────────────────────────────────────────

def _find_entry_offset(
    coff: ParsedCoff,
    text_base_offsets: dict[int, int],
    entry_name: str = "go",
) -> int:
    """Find entry point symbol offset in concatenated .text buffer."""
    candidates = [entry_name, f"_{entry_name}"]
    for sym in coff.symbols:
        if sym.name in candidates and sym.section_number > 0:
            idx = sym.section_number - 1
            if idx < len(coff.sections) and _classify_section(coff.sections[idx]) == "text":
                base = text_base_offsets.get(coff.sections[idx].section_index, 0)
                return base + sym.value
    raise CoffParseError(f"Entry point symbol '{entry_name}' not found in .text section")


# ── secType / funcType encoding ──────────────────────────

def _encode_sec_type(source_sec: int, coff_reloc_type: int) -> int:
    """Encode for RDATA/DATA/EXE relocations.

    Lower 8 bits  = source section (SEC_TEXT/SEC_RDATA/SEC_DATA)
    Upper 8 bits  = COFF relocation type
    """
    return (source_sec & 0xFF) | ((coff_reloc_type & 0xFF) << 8)


def _encode_func_type(func_index: int, coff_reloc_type: int) -> int:
    """Encode for DYNAMIC_FUNC_RELOC_TYPE relocations.

    Lower 8 bits  = function index in Beacon_Internal_Api (0-30)
                    or dynamicFns array (31+)
    Upper 8 bits  = COFF relocation type (REL32, ADDR64, etc.)
    """
    return (func_index & 0xFF) | ((coff_reloc_type & 0xFF) << 8)


# ── BOF argument packing ────────────────────────────────

def pack_bof_args(args: list[str]) -> bytes:
    """Pack BOF arguments.

    Each argument may carry a type prefix:
        s:value   → string (4-byte length + utf-8 bytes)
        i:value   → int32  (4 bytes)
        H:value   → int16  (2 bytes)
        A:value   → char   (1 byte)
    No prefix → auto: int if all digits, else string.
    """
    buf = bytearray()
    for arg in args:
        if not arg:
            continue
        if ":" in arg and arg[1] == ":" and arg[0] in ("s", "i", "H", "A"):
            typ, val = arg[0], arg[2:]
        else:
            typ, val = "s" if not arg.lstrip("-").isdigit() else "i", arg

        if typ == "i":
            buf += struct.pack("<i", int(val, 0))
        elif typ == "H":
            buf += struct.pack("<h", int(val, 0))
        elif typ == "A":
            buf += struct.pack("<b", int(val, 0) & 0xFF)
        else:  # 's'
            raw = val.encode("utf-8")
            buf += struct.pack("<I", len(raw)) + raw
    return bytes(buf)


# ── Blob builder ────────────────────────────────────────

def build_coff_blob(coff_data: bytes, entry_name: str = "go", bof_args: bytes = b"") -> bytes:
    """Parse COFF and build the binary blob for the implant."""
    coff = parse_coff(coff_data)

    # Classify and collect sections
    text_secs: list[CoffSection] = []
    rdata_secs: list[CoffSection] = []
    data_secs: list[CoffSection] = []
    bss_secs: list[CoffSection] = []
    sec_type_map: dict[int, str] = {}

    for sec in coff.sections:
        st = _classify_section(sec)
        sec_type_map[sec.section_index] = st
        if st == "text":
            text_secs.append(sec)
        elif st == "rdata":
            rdata_secs.append(sec)
        elif st == "data":
            data_secs.append(sec)
        elif st == "bss":
            bss_secs.append(sec)

    # Concatenate section data and track base offsets
    def _concat(sections: list[CoffSection], stype: str) -> tuple[bytes, dict[int, int]]:
        chunks: list[bytes] = []
        offsets: dict[int, int] = {}
        base = 0
        for s in sections:
            offsets[s.section_index] = base
            chunk = _section_raw_data(coff, s, stype)
            chunks.append(chunk)
            base += len(chunk)
        return b"".join(chunks), offsets

    code, text_base = _concat(text_secs, "text")
    rdata, rdata_base = _concat(rdata_secs, "rdata")
    data_data, data_base1 = _concat(data_secs, "data")
    bss_data, data_base2 = _concat(bss_secs, "bss")
    data = data_data + bss_data
    data_base = {**data_base1, **data_base2}

    if not text_secs:
        raise CoffParseError("No .text section found in COFF")

    # Find entry point
    entry_point = _find_entry_offset(coff, text_base, entry_name)

    # Build relocation entries
    reloc_entries: list[tuple[int, int, int, int]] = []
    func_names: list[str] = []
    func_name_map: dict[str, int] = {}

    # Track function index assignment: known Beacon functions get 0-30,
    # unknown Windows API functions get 31+ (into dynamicFns[]).
    func_index_map: dict[str, int] = {}
    next_dynamic_idx = DYNAMIC_FUNC_BASE

    def _resolve_func_index(name: str) -> int:
        nonlocal next_dynamic_idx
        if name not in func_index_map:
            if name in BEACON_INTERNAL_API_MAP:
                func_index_map[name] = BEACON_INTERNAL_API_MAP[name]
            else:
                if next_dynamic_idx >= DYNAMIC_FUNC_BASE + MAX_DYNAMIC_FUNCTIONS:
                    raise CoffParseError(
                        f"Exceeded max dynamic functions ({MAX_DYNAMIC_FUNCTIONS})"
                    )
                func_index_map[name] = next_dynamic_idx
                next_dynamic_idx += 1
        return func_index_map[name]

    def _func_name_offset(name: str) -> int:
        if name not in func_name_map:
            func_name_map[name] = sum(len(n) + 1 for n in func_names)
            func_names.append(name)
        return func_name_map[name]

    for src_name, src_sections, src_code in [
        ("text", text_secs, SEC_TEXT),
        ("rdata", rdata_secs, SEC_RDATA),
        ("data", data_secs + bss_secs, SEC_DATA),
    ]:
        for sec in src_sections:
            base_off = text_base.get(sec.section_index, 0) if src_name == "text" \
                else rdata_base.get(sec.section_index, 0) if src_name == "rdata" \
                else data_base.get(sec.section_index, 0)

            relocs = _read_relocations(coff, sec)
            if src_name != "text" and relocs:
                raise CoffParseError(
                    f"Relocations in .{src_name} sections are not supported by the current x64 BOF loader"
                )

            for reloc in relocs:
                sym = coff.symbol_map.get(reloc.symbol_table_index)
                if sym is None:
                    continue

                if sym.section_number > 0:
                    sn = sym.section_number
                    if sn not in sec_type_map:
                        continue
                    tgt_type = sec_type_map[sn]

                    if tgt_type == "rdata":
                        tgt_off = rdata_base.get(sn, 0) + sym.value
                        reloc_entries.append((
                            reloc.reloc_type,
                            RDATA_RELOC_TYPE,
                            base_off + reloc.virtual_address,
                            tgt_off,
                        ))
                    elif tgt_type in ("data", "bss"):
                        tgt_off = data_base.get(sn, 0) + sym.value
                        reloc_entries.append((
                            reloc.reloc_type,
                            DATA_RELOC_TYPE,
                            base_off + reloc.virtual_address,
                            tgt_off,
                        ))
                    elif tgt_type == "text":
                        tgt_off = text_base.get(sn, 0) + sym.value
                        reloc_entries.append((
                            reloc.reloc_type,
                            EXE_RELOC_TYPE,
                            base_off + reloc.virtual_address,
                            tgt_off,
                        ))
                else:
                    # External symbol → dynamic function
                    fname = sym.name
                    if not fname:
                        continue
                    # Strip __imp_ prefix (added by DECLSPEC_IMPORT)
                    if fname.startswith("__imp_"):
                        fname = fname[6:]
                    # Convert MODULE$Function → module.dll!Function
                    # (stored in name-string area, beacon resolves via LoadLibrary/GetProcAddress)
                    if "$" in fname:
                        parts = fname.split("$", 1)
                        fname = f"{parts[0].lower()}.dll!{parts[1]}"
                    func_idx = _resolve_func_index(fname)
                    # secType: if known API (0-30), store func_idx directly
                    #         if dynamic API (31+), store DYNAMIC_FUNC_RELOC_TYPE (1027)
                    sec_val = func_idx if func_idx < DYNAMIC_FUNC_BASE else DYNAMIC_FUNC_RELOC_TYPE
                    reloc_entries.append((
                        reloc.reloc_type,
                        sec_val,
                        base_off + reloc.virtual_address,
                        _func_name_offset(fname),
                    ))

    # END marker
    reloc_entries.append((0, END_RELOC_TYPE, 0, 0))

    # Pack relocation buffer
    reloc_buf = bytearray()
    for rt, st, rva, val in reloc_entries:
        reloc_buf += struct.pack(RELOC_STRUCT_FMT, rt, st, rva, val)
    # Append function name strings
    for name in func_names:
        reloc_buf += name.encode("ascii", errors="replace") + b"\x00"

    # Assemble final blob
    blob = bytearray()
    blob += struct.pack("<I", entry_point)
    blob += struct.pack("<I", len(code)) + code
    blob += struct.pack("<I", len(rdata)) + rdata
    blob += struct.pack("<I", len(data)) + data
    blob += struct.pack("<I", len(reloc_buf)) + bytes(reloc_buf)
    blob += struct.pack("<I", len(bof_args)) + bof_args
    return bytes(blob)


# ── Task preparation (called from api_routes) ──────────

def _resolve_path(raw_path: str) -> Path:
    if not raw_path or "\x00" in raw_path:
        raise CoffParseError("Invalid COFF path")
    p = Path(raw_path).expanduser()
    if not p.is_absolute():
        p = Path.cwd() / p
    return p.resolve()


def _split_args(args: str) -> list[str]:
    """Split shell-like arguments respecting quotes."""
    tokens: list[str] = []
    buf: list[str] = []
    quote: str | None = None
    for ch in args.strip():
        if quote:
            if ch == quote:
                quote = None
            else:
                buf.append(ch)
            continue
        if ch in ('"', "'"):
            quote = ch
            continue
        if ch.isspace():
            if buf:
                tokens.append("".join(buf))
                buf = []
            continue
        buf.append(ch)
    if quote:
        raise CoffParseError("Unclosed quote in arguments")
    if buf:
        tokens.append("".join(buf))
    return tokens


def prepare_inline_execute_task(args: str) -> tuple[str, str, dict[str, str | int]]:
    """Prepare an inline-execute task.

    Args:
        args: "<coff_path> [entry_name] [bof_args...]"

    Returns:
        (task_args, display_args, meta) where task_args is base64 blob.
    """
    parts = _split_args(args or "")
    if not parts:
        raise CoffParseError("Usage: inline-execute <path> [entry_name] [args...]")

    coff_path = _resolve_path(parts[0])
    if not coff_path.is_file():
        raise CoffParseError(f"COFF file not found: {parts[0]}")

    raw = coff_path.read_bytes()
    if len(raw) > 10 * 1024 * 1024:
        raise CoffParseError("COFF file exceeds 10 MB limit")

    entry_name = "go"
    bof_arg_tokens: list[str] = []

    if len(parts) >= 2:
        second = parts[1]
        # If second token matches a symbol name in the COFF, treat as entry name
        if second in _find_symbol_names(raw):
            entry_name = second
            bof_arg_tokens = parts[2:]
        else:
            bof_arg_tokens = parts[1:]

    bof_args = pack_bof_args(bof_arg_tokens)
    blob = build_coff_blob(raw, entry_name=entry_name, bof_args=bof_args)
    b64 = base64.b64encode(blob).decode("ascii")

    display = parts[0]
    if bof_arg_tokens:
        display += " " + " ".join(bof_arg_tokens)

    meta = {
        "coff_path": parts[0],
        "entry_name": entry_name,
        "blob_size": len(blob),
    }
    return b64, display, meta


def _find_symbol_names(coff_data: bytes) -> set[str]:
    """Return set of symbol names in the COFF (for entry-name detection)."""
    try:
        coff = parse_coff(coff_data)
        return {s.name for s in coff.symbols}
    except CoffParseError:
        return set()
