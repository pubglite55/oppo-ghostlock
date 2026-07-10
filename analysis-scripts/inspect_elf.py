#!/usr/bin/env python3
"""Inspect vmlinux.elf structure."""
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

VMLINUX = "/Users/xiuxiu391/Desktop/oppo/vmlinux.elf"

with open(VMLINUX, "rb") as f:
    elf = ELFFile(f)
    print(f"Machine: {elf.header.e_machine}")
    print(f"Class: {elf.header.e_ident.EI_CLASS}")
    print(f"Endian: {elf.header.e_ident.EI_DATA}")
    print(f"Entry: 0x{elf.header.e_entry:x}")
    print(f"Type: {elf.header.e_type}")
    print()

    print("Sections:")
    for i, section in enumerate(elf.iter_sections()):
        name = section.name
        addr = section["sh_addr"]
        size = section["sh_size"]
        offset = section["sh_offset"]
        flags = section["sh_flags"]
        print(f"  [{i:3d}] {name:30s} addr=0x{addr:010x} size=0x{size:010x} offset=0x{offset:010x} flags=0x{flags:x}")

    print()

    # Check if .text is actually progbits
    text = elf.get_section_by_name(".text")
    if text:
        print(f".text type: {text.header.sh_type}")
        print(f".text flags: 0x{text['sh_flags']:x}")
        # Read first 64 bytes
        data = text.data()
        print(f".text first 64 bytes: {data[:64].hex()}")

    # Check for .symtab
    print("\nSymbol tables:")
    for section in elf.iter_sections():
        if isinstance(section, SymbolTableSection):
            count = section.num_symbols()
            print(f"  {section.name}: {count} symbols")
            for sym in list(section.iter_symbols())[:10]:
                print(f"    {sym.name!r}: value=0x{sym.entry.st_value:x} size={sym.entry.st_size} type={sym.entry.st_info & 0xf}")

    # Check for compressed sections (SHT_PROGBITS with .z prefix)
    print("\nLooking for compressed sections...")
    for section in elf.iter_sections():
        if section.name.startswith(".z") or section.name.startswith("z."):
            print(f"  {section.name}: offset=0x{section['sh_offset']:x} size=0x{section['sh_size']:x}")

    # Check if there's a .rodata or .data section with lots of data
    rodata = elf.get_section_by_name(".rodata")
    if rodata:
        print(f"\n.rodata: addr=0x{rodata['sh_addr']:x} size=0x{rodata['sh_size']:x}")

    # Look for KALLSYMS or string table that might have function names
    print("\nAll section names:")
    for section in elf.iter_sections():
        print(f"  {section.name}")
