#!/usr/bin/env python3
"""
Petite x64 unpacker, owed this release to someone lmao

Petite is frankly old and only has the x86 version available for download in their site (or did the last time I checked), this is a x64 build that I found some in-house
binaries using. Although porting it to x86 should be easy enough, given the compression algorithm is almost the same and even uses the same windows, would mostly be a
matter of fixing types, sizes and PE info really.

v2 cause v1 is probably between a few old backups and uses pefile & lief in ways I don't even want to bother to find and rebuild, plus it barely worked
and couldn't produce a reproducible or interchangeable version as far as I'm concerned.

If anyone even comes across this, you'll find that the script is severely lacking in features, checks, comments - yeah I know, this was done just out of boredom and to
test some harnesses on some libraries that were using Petite as packer... not that it matters since you can just use the packed version and let the unpacker do it's thing,
but I figured this would be useful for static analysis, and since there was no public Petite packer for this type of thing afaik...

Anyway, enough yapping.


Couple features:

    - Fixed Exception data directory
    - Fixed Resources data directory
    - Added import/export relocation
    - Added reloc support

    
TODO: Fix some more data directories (specially Debug, saw a sample use it)
      Stop hardcoding header length
      Check some loop bounds in the decompression algorithm
      Add x86 support? Not that it's needed for now really, although most usage of Petite did happen in the x86 days

"""


import argparse
import lief

from dataclasses import dataclass
from struct import unpack, pack, pack_into, unpack_from

# Yeah! STFU!
lief.logging.disable()



@dataclass
class PackData:
    """Class representing basic packed-data information"""

    # You could technically just pass read_start 0 if packed_data contains just the packaged data, but this was written with passing the whole packed section in mind, so
    xor_key: int
    read_start: int
    packed_data: bytes


    def dump(self) -> None:
        print (f"Unpacked length: {hex(self.xor_key)}")
        print (f"Read start: {hex(self.read_start)}")
        print (f"Byte length: {hex(len(self.packed_data))}")
                

@dataclass
class FragmentData:

    rva_packed: int # RVA of packed data
    size_after_unpacking: int # Size of unpacked data
    destination_rva: int # RVA where data will be written
    vp_size: int # Size the VirtualProtect call will use (the first significant bit is used for something else inside the packer, divide between 2 to get the actual result)
    unk_dw4: int # Unknown, but if non-zero, the packed fragment data will be copied to the loader page allocation before decompressing it into the PE, has no purpose for what we do really
    mem_prot: int # Byte representing the memory protection the fragment will use


def generate_empty_pe() -> lief.PE.Binary:
    """Returns an empty PE32+/PE64 object as the lief.PE.Binary type"""

    raw_pe_header = (
        # DOS header
        b"\x4D\x5A\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00\xFF\xFF\x00\x00\xB8\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x80\x00\x00\x00"
        b"\x0E\x1F\xBA\x0E\x00\xB4\x09\xCD\x21\xB8\x01\x4C\xCD\x21\x54\x68\x69\x73\x20\x70\x72\x6F\x67\x72\x61\x6D\x20\x63\x61\x6E\x6E\x6F"
        b"\x74\x20\x62\x65\x20\x72\x75\x6E\x20\x69\x6E\x20\x44\x4F\x53\x20\x6D\x6F\x64\x65\x2E\x0D\x0D\x0A\x24\x00\x00\x00\x00\x00\x00\x00"

        # NT headers
        b"\x50\x45\x00\x00\x64\x86\x00\x00\x44\x33\x22\x11\x00\x00\x00\x00\x00\x00\x00\x00\xF0\x00\x22\x20\x0B\x02\x0A\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x02\x00\x00"
        b"\x05\x00\x02\x00\x02\x00\x04\x00\x05\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x40\x01"
        b"\x00\x00\x10\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00"
    )

    pe = lief.PE.parse(raw_pe_header)

    if not pe:
        raise RuntimeError("Couldn't generate template PE, check your lief installation!")

    return pe

def get_loader_pd(pe: lief.PE.Binary) -> PackData:
    """Get PackData for the packed loader, rudimentary for now as you can see by the raw offset reading"""

    # ALLOC_SIZE_OFFSET, ALLOC_SIZE_WIDTH = 0x56, 0x04
    XOR_KEY_OFFSET, XOR_KEY_WIDTH       = 0x6C, 0x04
    READ_START_OFFSET, READ_START_WIDTH = 0x73, 0x04

    PETITE_SECTION_NUMBER = 2

    # alloc_size = unpack('<i', pe.sections[PETITE_SECTION_NUMBER].content[ALLOC_SIZE_OFFSET:ALLOC_SIZE_OFFSET + ALLOC_SIZE_WIDTH].tobytes())[0]
    xor_key    = unpack('<i', pe.sections[PETITE_SECTION_NUMBER].content[XOR_KEY_OFFSET:XOR_KEY_OFFSET + XOR_KEY_WIDTH].tobytes())[0]
    read_start = unpack('<i', pe.sections[PETITE_SECTION_NUMBER].content[READ_START_OFFSET:READ_START_OFFSET + READ_START_WIDTH].tobytes())[0] - pe.sections[0].virtual_address # -rva since we're working with assumed base zero

    return PackData(xor_key, read_start, pe.sections[0].content.tobytes())

def get_fragments_from_loader(loader_data: bytearray) -> list[FragmentData]:
    """Extract the list of fragments found inside the fragment table of a given loader"""

    FRAGMENTS_OFFSET_OFFSET = 0x0D
    FRAGMENTS_OFFSET_WIDTH  = 0x04

    fragment_offset = unpack('<I', loader_data[FRAGMENTS_OFFSET_OFFSET:FRAGMENTS_OFFSET_OFFSET + FRAGMENTS_OFFSET_WIDTH])[0]

    # add the bytearray to not raise an exception on access to an invalid entry
    frag_table = loader_data[fragment_offset:] + bytearray(256)

    # maybe enable this if there's ever a debug mode or smth
    # print (f"Fragment Table @loader+{hex(fragment_offset)}")
    # print (f"Not all fragments are sections - etc, etc.")

    i = 0
    sizeof_frag_row = 0x15
    fragments: list[FragmentData] = []

    while True:

        rva_packed = unpack('<I', frag_table[0 + (i * sizeof_frag_row):(i * sizeof_frag_row) + 4])[0]

        if rva_packed == 0:
            break

        size_after_unpacking = unpack('<I', frag_table[4 + i * sizeof_frag_row:4 + (i * sizeof_frag_row) + 4])[0]
        destination_rva = unpack('<I', frag_table[8 + i * sizeof_frag_row:8 + (i * sizeof_frag_row) + 4])[0]
        vp_size = unpack('<I', frag_table[12 + i * sizeof_frag_row:12 + (i * sizeof_frag_row) + 4])[0]
        dword_4 = unpack('<I', frag_table[16 + i * sizeof_frag_row:16 + (i * sizeof_frag_row) + 4])[0]

        mem_prot = unpack('B', frag_table[20 + i * sizeof_frag_row:20 + (i * sizeof_frag_row) + 1])[0]

        print (f"Fragment {i} -> Packed RVA: {rva_packed:#7x}, Output size: {size_after_unpacking:#7x}, Destination RVA: {destination_rva:#7x}, VirtualProtect size (pre-shr): {vp_size:#7x}, UnknownDW4: {dword_4:#7x}, Memory Protection: {mem_prot:#2x}")

        fragments.append(FragmentData(rva_packed, size_after_unpacking, destination_rva, vp_size, dword_4, mem_prot))

        i += 1

    return fragments

def unpack_pd(pd: PackData) -> bytearray:
    """
    Function to unpack data packaged by Petite.

    As a disclaimer: I'm very obviously not an expert on compression or anything of the sort, and the algorithm was implemented from reverse-engineering a packed PE's loader,
    I BELIEVE, keyword, BELIEVE, this algorithm to be a LZ77 NRV2B(D/E?)-adjacent mod, as it decompresses data by replacing repeating patterns with references to previous appearences. 
    It uses a negative offset into the previously decoded output stream, this being controlled by a general control bitstring that defines when, where and what to copy.
    """

    def next_bitstring_bit() -> bool:

        # sigh
        nonlocal bitstring, read_ptr

        bitstring <<= 1
        old_bitstring = bitstring
        bitstring &= 0xFFFFFFFF # emulate overflow

        # If the whole control bitstream has been consumed, retrieve a new one from the current read pointer
        if bitstring == 0:

            # changed to <I from <i so the value is unsigned and doesn't fail the >-4 check
            bitstring = unpack('<I' , pd.packed_data[read_ptr:read_ptr + 4])[0]

            read_ptr += 4 # sub rsi, 0xFFFFFFFFFFFFFFFC

            # Get bit now that we can
            bitstring <<= 1
            old_bitstring = bitstring
            bitstring &= 0xFFFFFFFF

            # To simulate the behavior of ADC, as the SUB used to add 4 to read_ptr sets CF if destination (rsi) is lower than source (0xFFFFFFFFFFFFFFFC / -4)
            # Guess it's setting up the last bit on control to mark this as the last and not have premature control bitstring fetching
            if (read_ptr - 4) > -4:
                bitstring += 1
                old_bitstring += 1

        return old_bitstring > 0xFFFFFFFF


    def calc_copy_len():

        nonlocal copy_len

        # print (f"[UNK] bitstring by the start of calc_copy_len: {hex(bitstring)}, copy_len by start: {hex(copy_len)}")

        copy_len += 1

        while True:

            cf = 1 if next_bitstring_bit() else 0
            copy_len <<= 1 
            copy_len += cf
            copy_len &= 0xFFFFFFFF

            # print (f"[UNK] copy_len after iter: {hex(copy_len)}, cf: {cf}")

            if not next_bitstring_bit():
                
                # print (f"[UNK] bitstring by the END of calc_copy_len: {hex(bitstring)}, copy_len by end: {hex(copy_len)}")
                return


    # the good times when copy_len was called ecx...
    bitstring, copy_len = 0, 0
    last_copy_offset = -1

    xor_key = pd.xor_key
    read_ptr = pd.read_start

    out_ptr = 0
    out = bytearray(pd.xor_key + 1)

    atomic = True

    # Set A, B & C based on unpacking length, would have to guess it's related to encoder settings
    if xor_key >= 0x10_000:
        def_copy_len = 8
        b = -32000
        c = -1280

    else:
        def_copy_len = 5
        b = -16288
        c = -928

    while xor_key > 0:

        if atomic:

            # print (f"[ATOMIC] Executing atomic operation...")

            # Atomic operations write the XOR result of the current decreasing XOR key/size on the current byte pointed at by the read pointer inside the whole data block
            out[out_ptr] = (xor_key ^ pd.packed_data[read_ptr]) & 0xFF
            
            read_ptr += 1
            out_ptr += 1

            xor_key -= 1

        # technically the xor_key > 0 check should be done before calling next_bitstring_bit
        if xor_key == 0:
            break

        # If the next control bit is set, it means there's a multi-byte copy
        if next_bitstring_bit():

            r8 = 0
            calc_copy_len() # sets copy_len internally

            copy_len -= 3

            if copy_len < 0:
                copy_offset = last_copy_offset # mov rax, r9
                copy_len += 1

            else:

                eax = copy_len
                copy_len = def_copy_len

                cf = 1 if next_bitstring_bit() else 0
                eax += eax + cf

                # added the -1 cause naturally it was doing +1 loop but idk
                # TODO: check if the copy_len - 1 is valid or makes sense, because we don't do this in the rep movsb loop
                for _ in range(0, copy_len - 1):
                    cf = 1 if next_bitstring_bit() else 0
                    eax += eax + cf

                # it's a loop in asm, which decreases copy_len
                copy_len = 0

                # print (f"eax after loop: {hex(eax)}")

                # NOT the 64-bit value & then convert it to a signed integer
                eax = ~eax & 0xFFFFFFFFFFFFFFFF
                eax = eax - (1 << 64) if eax & (1 << 63) else eax

                # print (f"~eax -> {hex(eax)}, int: {eax}")

                # cmp rax, c

                cf = 1 if eax < c else 0
                # print (f"cmp {hex(eax)}, {hex(c)} -> CF: {cf}")
                r8 += 1 + cf

                # cmp rax, b
                
                cf = 1 if eax < b else 0
                # print (f"cmp rax, b -> CF: {cf}")
                r8 += cf

                #  print (f"r8 by the end: {hex(r8)}")
                
                copy_offset = eax

                # mov r9, rax - update the r9 value
                last_copy_offset = eax


            # print (f"copy_len before copy_len preparations: {hex(copy_len)}")

            # after the copy_len preparations before
            cf = 1 if next_bitstring_bit() else 0
            copy_len <<= 1
            copy_len += cf
            copy_len &= 0xFFFFFFFF
            
            cf = 1 if next_bitstring_bit() else 0
            copy_len <<= 1
            copy_len += cf
            copy_len &= 0xFFFFFFFF

            # print (f"copy_len after copy_len preparations: {hex(copy_len)}")

            if copy_len == 0:
                calc_copy_len()
                copy_len += 2

            copy_len += r8
            xor_key -= copy_len

            # print (f"xor_key = {hex(xor_key)} (after substracting copy_len: {hex(copy_len)})")

            # jb to end
            if xor_key < 0:
                break

            # print (f"[COPYDATA] rep movsb from {hex(out_ptr + copy_offset)} to {hex(out_ptr)}, size: {hex(copy_len)}")

            for i in range(0, copy_len):
                out[out_ptr + i] = out[out_ptr + copy_offset + i]

            out_ptr += copy_len

            # Reset write size after writing
            copy_len = 0

            atomic = False

        else:
            atomic = True

    # print (f"LOOP DONE, read_ptr: {hex(read_ptr)}, out_ptr: {hex(out_ptr)}")
    # at this point out_ptr is the length of the output block, exact and out[:out_ptr] is the decoded block

    return out[:out_ptr]

def populate_pe(original_pe: lief.PE.Binary, frags: list[FragmentData], noted_replacement_byte: int) -> lief.PE.Binary:

    def memprot2char(mem_prot: int) -> int:
        """To convert between windows VirtualProtect-style page protection constants and section characteristics, more or less"""

        match mem_prot:

            # Added the "contains code" flag to these (0x20)

            case 0x10: # PAGE_EXECUTE
                return 0x20000020
            case 0x20: # PAGE_EXECUTE_READ
                return 0x60000020
            case 0x40: # PAGE_EXECUTE_READWRITE
                return 0xE0000020

            # PAGE_EXECUTE_WRITECOPY skipped

            case 0x01: # PAGE_NOACCESS
                return 0x00000000
            case 0x02: # PAGE_READONLY
                return 0x40000000
            case 0x04: # PAGE_READWRITE
                return 0xC0000000

            case _:
                return 0xF0000000 # Shareable RWX characteristics
            # PAGE_WRITECOPY skipped
            # PAGE_TARGETS_INVALID skipped
            # PAGE_TARGETS_NO_UPDATE skipped

            # Needlessly to say, non-translatable memory protection modifiers such as PAGE_GUARD, PAGE_NOCACHE & PAGE_WRITECOMBINE are not included
            # Neither are SGXs since once again they have no direct correspondence with section characteristics, rather obviously

    new_pe = generate_empty_pe()

    for i, frag in enumerate(reversed(frags)):

        if frag.destination_rva > original_pe.sections[0].virtual_address + original_pe.sections[0].virtual_size:
            print (f"Fragment {len(frags) - i} writes outside packed region... (dest rva: {frag.destination_rva:#x} - relocs? (+ {frag.destination_rva - original_pe.sections[0].virtual_address + original_pe.sections[0].virtual_size:#x}))")
            continue

        sec = lief.PE.Section(f".sec{i}")

        # Remove packed section RVA from fragment source RVA since the unpack function works with base 0
        frag.rva_packed -= original_pe.sections[0].virtual_address

        print (f"Unpacking section {i} -> xor: {frag.size_after_unpacking:#x}, read_ptr: {frag.rva_packed:#x}, out_rva: {frag.destination_rva:#x}")

        upk_data = unpack_pd(PackData(frag.size_after_unpacking, frag.rva_packed, bytes(original_pe.sections[0].content)))

        sec.name = f".sec{i}"
        sec.virtual_address = frag.destination_rva
        sec.characteristics = memprot2char(frag.mem_prot)
        

        sec.virtual_size = frag.vp_size // 2


        # Do fixes here I guess
        if frag.vp_size & 0x01:
            print (f"Section is code, resolving relative CALLs/JCCs/JMPs (notice byte: {noted_replacement_byte:#x})...")

            size = frag.size_after_unpacking - 6
            ptr  = 0

            while ptr < size:                

                ins_bytes = unpack('<I', upk_data[ptr: ptr + 4])[0]
                ptr += 1

                # Check if the current instruction is a CALL, JMP or JCC NEAR
                # TODO: Okay this is getting kinda silly, one sample compared against values starting with 0x14, then the other one by 0x0A. I guess we could make this more general
                #       with a pattern like ??E8 (well - that's just E8 really), but so far I'm working with just two samples and am not interested in more at the moment, so yeah

                
                # Funny bug I caught after testing the output DLL, some PEs use say, 0x14 for the value, some 0x0A, I guess it could be anything, but it's only that, anything else is not intended to happen,
                # so originally it ended up patching stuff that was not supposed to be patched
                if (ins_bytes & 0xFFFF) == ((noted_replacement_byte << 8) + 0xE8) or (ins_bytes & 0xFFFF) == ((noted_replacement_byte << 8) + 0xE9) or (ins_bytes & 0xFFF0FF) == ((noted_replacement_byte << 16) + 0x800F):

                    if (ins_bytes & 0xFFF0FF) == ((noted_replacement_byte << 16) + 0x800F):
                        ptr += 1

                    # endianness sorcery, it actually makes sense somehow
                    eax = unpack('<I', upk_data[ptr: ptr + 4])[0]

                    eax &= ~0xFF
                    eax = int.from_bytes((eax & 0xFFFFFFFF).to_bytes(4, "little"), "big", signed = False)

                    ptr += 4
                    eax -= ptr

                    # write fixed address
                    upk_data[ptr - 4:ptr] = int(eax).to_bytes(4, "little", signed = True)

            # After this loop the unpacking routine also does like...
            # fill N = (((frag.vp_size >> 1) - frag.size_after_unpacking) / 4) DWORDs after the fixed section with zeros, for some reason
            # then ((frag.size_of_virtualprotect >> 1) - frag.size_after_unpacking) & 3 bytes to zero too
            
            # print (f"TODO or something but we should (may?) clean the bytes after the writes as in the loader, or maybe not, idk")

        sec.content = memoryview(upk_data)
        new_pe.add_section(sec)


    # TODO: fix this hardcoding, as the raw offset into the first section may end up pointing to the section table if this surpasses 0x400 bytes
    new_pe.optional_header.sizeof_headers = 0x400

    raw_offset = new_pe.optional_header.sizeof_headers

    for sec in new_pe.sections:
        sec.pointerto_raw_data = raw_offset
        sec.sizeof_raw_data = len(sec.content)

        raw_offset = (raw_offset + sec.sizeof_raw_data + 0x1FF) & ~0x1FF

    # Fix optional header
    new_pe.optional_header.baseof_code = original_pe.optional_header.baseof_code
    new_pe.optional_header.imagebase = original_pe.optional_header.imagebase

    return new_pe

def fix_data_dirs(original_pe: lief.PE.Binary, new_pe: lief.PE.Binary, fragments: list[FragmentData], redo_exports: bool = False, repack_resources: bool = False) -> lief.PE.Binary:

    new_pe.exceptions_dir.rva = original_pe.exceptions_dir.rva
    new_pe.exceptions_dir.size = original_pe.exceptions_dir.size

    if repack_resources:
        
        print("Repackaging resources...")

        res_dir = original_pe.data_directory(lief.PE.DataDirectory.TYPES.RESOURCE_TABLE)
        res_data = bytes(original_pe.get_content_from_virtual_address(res_dir.rva, res_dir.size))

        rsrc_section = lief.PE.Section(".rsrc")
        rsrc_section.content = memoryview(res_data)
        rsrc_section.characteristics = 0x40000040

        rsrc_section = new_pe.add_section(rsrc_section)

        if rsrc_section is None:
            raise RuntimeError("Failed to create .rsrc section")

        new_res_dir = new_pe.data_directory(lief.PE.DataDirectory.TYPES.RESOURCE_TABLE)

        new_res_dir.rva = rsrc_section.virtual_address
        new_res_dir.size = res_dir.size

        rsrc_section.virtual_size = (res_dir.size + 0x1FF) & ~0x1FF
        
        rsrc_section.sizeof_raw_data = res_dir.size

        print (f"Resource section VA: {rsrc_section.virtual_address:#x}, size: {res_dir.size:#x}")


    if redo_exports:

        print("Creating export table...")

        export_data = bytes(original_pe.get_content_from_virtual_address(original_pe.export_dir.rva, original_pe.export_dir.size))

        # Get all export data stuff
        chars = unpack('<I', export_data[0:4])[0]
        timedatestamp = unpack('<I', export_data[4:8])[0]
        major_version = unpack('<H', export_data[8:10])[0]
        minor_version = unpack('<H', export_data[10:12])[0]
        name_rva = unpack('<I', export_data[12:16])[0]
        base = unpack('<I', export_data[16:20])[0]
        num_funcs = unpack('<I', export_data[20:24])[0]
        num_names = unpack('<I', export_data[24:28])[0]
        addr_funcs = unpack('<I', export_data[28:32])[0]
        addr_names = unpack('<I', export_data[32:36])[0]
        addr_ordns = unpack('<I', export_data[36:40])[0]

        content = bytearray(b"\x00" * 40)

        # AddressOfFunctions
        funcs_offset = len(content)

        for i in range(num_funcs):

            exp_func_rva = unpack('<I',  original_pe.get_content_from_virtual_address(addr_funcs + (i * 4), 4))[0]

            content += pack('<I', exp_func_rva)

        # AddressOfNames
        names_offset = len(content)
        name_rva_positions = []

        for i in range(num_names):
            name_rva_positions.append(len(content))
            content += b"\x00" * 4

        # AddressOfNameOrdinals
        ordns_offset = len(content)

        for i in range(num_names):
            ordinal_index = unpack('<H', bytes(original_pe.get_content_from_virtual_address(addr_ordns + (i * 2), 2)))[0]
            content += pack('<H', ordinal_index)

        # DLL name
        dll_name = bytes(original_pe.get_content_from_virtual_address(name_rva, 256)).split(b'\x00', 1)[0]

        dll_name_offset = len(content)
        content += dll_name + b'\x00'

        # Export names
        export_name_offsets = []

        for i in range(num_names):

            exp_name_rva = unpack('<I', bytes(original_pe.get_content_from_virtual_address(addr_names + (i * 4), 4)))[0]

            exp_name = bytes(original_pe.get_content_from_virtual_address(exp_name_rva, 256)).split(b'\x00', 1)[0]

            export_name_offsets.append(len(content))
            content += exp_name + b'\x00'

        # Create .edata section - was gonna be .iedata for both imports + exports at first but meh
        edata_section = lief.PE.Section(".edata")
        edata_section.content = memoryview(content)
        edata_section.characteristics = 0x40000040

        edata_section = new_pe.add_section(edata_section)

        if edata_section is None:
            raise RuntimeError("Failed to create .edata section")

        edata_rva = edata_section.virtual_address

        content = bytearray(edata_section.content)

        # Set up all the export data directory info
        pack_into('<I', content, 0, chars)
        pack_into('<I', content, 4, timedatestamp)
        pack_into('<H', content, 8, major_version)
        pack_into('<H', content, 10, minor_version)
        pack_into('<I', content, 12, edata_rva + dll_name_offset)
        pack_into('<I', content, 16, base)
        pack_into('<I', content, 20, num_funcs)
        pack_into('<I', content, 24, num_names)
        pack_into('<I', content, 28, edata_rva + funcs_offset)
        pack_into('<I', content, 32, edata_rva + names_offset)
        pack_into('<I', content, 36, edata_rva + ordns_offset)

        for i, name_offset in enumerate(export_name_offsets):
            pack_into('<I', content, name_rva_positions[i], edata_rva + name_offset)

        edata_section.content = memoryview(content)

        new_pe.export_dir.rva = edata_rva
        new_pe.export_dir.size = len(content)

        print (f"Export section written, VA: {edata_rva:#x}, size: {len(content):#x}")

    return new_pe

def fix_imports(original_pe: lief.PE.Binary, new_pe: lief.PE.Binary, unk_addr_struct_rva: int) -> lief.PE.Binary:

    print(f"Starting import fixes assuming unknown Petite import struct being at RVA {unk_addr_struct_rva:#x}")

    imports = []
    c_ptr = unk_addr_struct_rva

    while unpack('<I', new_pe.get_content_from_virtual_address(c_ptr, 4))[0] != 0:

        ilt_entries_rva = unpack('<I', new_pe.get_content_from_virtual_address(c_ptr, 4))[0]
        dll_name_rva = unpack('<I', new_pe.get_content_from_virtual_address(c_ptr + 4, 4))[0]

        # for some reason DLL names are stored after 
        dll_name_rva += original_pe.iat_dir.rva

        dll_name = bytes(original_pe.get_content_from_virtual_address(dll_name_rva, 256)).split(b'\x00', 1)[0]
        dll_name = dll_name.decode('ascii')

        functions = []

        ilt_entry_rva = ilt_entries_rva

        # print(f"Exploring ILT @ RVA {ilt_entry_rva:#x}")

        while True:

            c_entry = unpack('<Q', new_pe.get_content_from_virtual_address(ilt_entry_rva, 8))[0]

            if c_entry == 0:
                break

            if c_entry & 0x8000000000000000:

                ordinal = c_entry & 0xffff

                # print(f"Unk import struct entry @{c_ptr:#x}; ILT entry: {ilt_entry_rva:#x}, func: {dll_name}!#{ordinal}")

                functions.append({"ordinal": ordinal, "name": None})

            else:

                c_entry_name = bytes(new_pe.get_content_from_virtual_address(c_entry, 256)).split(b'\x00', 1)[0]
                c_entry_name = c_entry_name.decode('ascii')

                # print(f"Unk import struct entry @{c_ptr:#x}; ILT entry: {ilt_entry_rva:#x}, func: {dll_name}!{c_entry_name}")

                functions.append({"ordinal": None, "name": c_entry_name})


            functions[-1]["iat_rva"] = ilt_entry_rva

            ilt_entry_rva += 8

        imports.append({"dll": dll_name, "functions": functions})

        c_ptr += 8


    # Make up the new .idata section, IAT stays the same ofc since the original functions need it after all

    descriptor_size = 20
    descriptor_count = len(imports) + 1


    content = bytearray(descriptor_count * descriptor_size)
    layout = []


    for imp in imports:

        function_count = len(imp["functions"]) + 1
        ilt_offset = len(content)

        content.extend(b'\x00' * (function_count * 8))

        layout.append({
            "dll": imp["dll"],
            "functions": imp["functions"],
            "ilt_offset": ilt_offset,
        })

    # DLl names since Petite takes them for some reason
    for item in layout:

        item["dll_offset"] = len(content)
        content.extend(item["dll"].encode('ascii') + b'\x00')

    # IMAGE_IMPORT_BY_NAME
    for item in layout:

        for func in item["functions"]:

            if func["name"] is None:
                continue

            func["name_offset"] = len(content)

            content.extend(pack('<H', 0))
            content.extend(func["name"].encode('ascii') + b'\x00')


    # If you stare at the abyss for long enough, the abyss will stare back
    idata_rva = ((new_pe.sections[-1].virtual_address + new_pe.sections[-1].virtual_size + new_pe.optional_header.section_alignment - 1) // new_pe.optional_header.section_alignment) * new_pe.optional_header.section_alignment

    print(f"Predicted .idata RVA: {idata_rva:#x}")

    for index, item in enumerate(layout):

        descriptor_offset = index * descriptor_size
        first_thunk_rva = item["functions"][0]["iat_rva"]

        # IMAGE_IMPORT_DESCRIPTOR
        descriptor_data = pack(
            '<IIIII',
            idata_rva + item["ilt_offset"], # OriginalFirstThunk
            0, # TimeDateStamp
            0, # ForwarderChain
            idata_rva + item["dll_offset"], # Name
            first_thunk_rva # FirstThunk
        )

        content[descriptor_offset:descriptor_offset + descriptor_size] = descriptor_data

        # Overwrite ILT entries
        for func_index, func in enumerate(item["functions"]):

            ilt_val = (0x8000000000000000 | func["ordinal"]) if func["ordinal"] else idata_rva + func["name_offset"]
            ilt_offset = item["ilt_offset"] + (func_index * 8)

            content[ilt_offset:ilt_offset + 8] = pack('<Q', ilt_val)

    # Add section
    idata_section = lief.PE.Section(".idata")

    idata_section.content = memoryview(content)
    idata_section.characteristics = 0xC0000040 # RW + initialized

    added_section = new_pe.add_section(idata_section)

    if added_section is None:
        raise RuntimeError("Failed to add .idata section")


    if added_section.virtual_address != idata_rva:
        raise RuntimeError(f".idata was placed at {added_section.virtual_address:#x}, but was expected to be @{idata_rva:#x}")

    new_pe.import_dir.rva = idata_rva
    new_pe.import_dir.size = descriptor_count * descriptor_size


    # IAT patching
    iat_entries = []

    for item in layout:

        for func in item["functions"]:
            iat_entries.append(func["iat_rva"])

    if iat_entries:
        new_pe.iat_dir.rva = min(iat_entries)
        new_pe.iat_dir.size = max(iat_entries) - min(iat_entries) + 8

    else:
        raise RuntimeError("Couldn't patch IAT, iat_entries empty for whatever reason")

    print(f"Import directory -> RVA: {new_pe.import_dir.rva:#x}, size: {new_pe.import_dir.size:#x}")
    print(f"IAT directory -> RVA: {new_pe.iat_dir.rva:#x}, size: {new_pe.iat_dir.size:#x}")

    return new_pe

def fix_relocations(original_pe, pe, frags):

    reloc_stream = None

    for frag in frags:
        if frag.destination_rva > original_pe.sections[0].virtual_address + original_pe.sections[0].virtual_size:

            reloc_data = bytes(original_pe.get_content_from_virtual_address(frag.rva_packed, frag.size_after_unpacking))
            reloc_stream = unpack_pd(PackData(frag.size_after_unpacking, 0, reloc_data))

            if reloc_stream:
                break

    if not reloc_stream:
        raise RuntimeError("Couldn't find reloc")

    # Funny algorithm, literally generated given the asm, can't even bother
    targets = []
    pos = 0
    current_rva = 0

    while pos < len(reloc_stream):
        first = reloc_stream[pos]

        if first != 0:
            delta = first
            pos += 1
        else:
            if pos + 4 > len(reloc_stream):
                raise ValueError(f"Truncated relocation stream at {pos:#x}")

            value = unpack_from("<I", reloc_stream, pos)[0]
            pos += 4

            if value == 0:
                break

            delta = value >> 8

        current_rva += delta
        targets.append(current_rva)

    if not targets:
        raise RuntimeError("No relocations found")

    imagebase = pe.optional_header.imagebase
    section_buffers = {
        section.name: bytearray(section.content)
        for section in pe.sections
    }

    for rva in targets:
        target_section = None
        section_offset = None

        for section in pe.sections:
            start = section.virtual_address
            end = start + len(section.content)

            if start <= rva and rva + 8 <= end:
                target_section = section
                section_offset = rva - start
                break

        if target_section is None:
            print(f"reloc target {rva:#x} outside section content")
            continue

        buf = section_buffers[target_section.name]

        if not section_offset:
            print ("TODO: whatever this is")
            continue

        if section_offset + 8 > len(buf):
            print(f"reloc target {rva:#x} exceeds section buffer")
            continue

        old_bytes = bytes(buf[section_offset:section_offset + 8])

        swapped = int.from_bytes(old_bytes, byteorder="big")
        decoded = (swapped + imagebase) & 0xffffffffffffffff

        buf[section_offset:section_offset + 8] = pack("<Q", decoded)


    for section in pe.sections:
        old_content = bytes(section.content)
        new_content = bytes(section_buffers[section.name])

        if old_content != new_content:
            section.content = list(new_content)


    # Build standard PE relocation blocks
    pages = {}

    for rva in targets:
        page_rva = rva & ~0xFFF
        offset = rva & 0xFFF
        entry = (10 << 12) | offset
        pages.setdefault(page_rva, []).append(entry)

    for entries in pages.values():
        entries.sort()

    content = bytearray()

    for page_rva in sorted(pages):
        block = bytearray()

        for entry in pages[page_rva]:
            block += pack("<H", entry)

        if len(block) % 4:
            block += pack("<H", 0)

        block_size = 8 + len(block)
        content += pack("<II", page_rva, block_size)
        content += block

    if not content:
        raise RuntimeError("Generated relocation table is empty")

    # Add the section
    section = lief.PE.Section(".reloc")
    section.content = memoryview(content)
    section.characteristics = 0x40000000 # Readonly

    reloc_section = pe.add_section(section)

    if reloc_section is None:
        raise RuntimeError("Failed to add .reloc section")

    pe.relocation_dir.rva = reloc_section.virtual_address
    pe.relocation_dir.size = len(content)

    return pe


def get_args():

    # Could probably make the options a bit less lmao but yeah
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', help = 'File to unpack')
    parser.add_argument('-r', '--resources', action = 'store_true', help = 'Re-package resources in a new section')
    parser.add_argument('-i', '--imports', action = 'store_true', help = 'Recreate import table')
    parser.add_argument('-e', '--exports', action = 'store_true', help = 'Recreate export table')
    parser.add_argument('-l', '--relocs', action = 'store_true', help = 'Convert relocs from the current Petite format to default Windows relocs')

    args = parser.parse_args()

    return args

def main():

    args = get_args()

    if not args.file:
        print ("No file provided")
        return

    pe = lief.parse(args.file)

    if not pe or type(pe) != lief.PE.Binary:
        print ("Couldn't parse PE!")
        return -1


    if len(pe.sections) != 3 or pe.sections[2].name != "petite":
        print ("File doesn't seem to be packed by Petite!")
        return -1

    else:
        print ("File packed with Petite")

    loader = unpack_pd(get_loader_pd(pe))
    frags = get_fragments_from_loader(loader)

    print ("Extracted fragment data, rebuilding PE...")

    new_pe = populate_pe(pe, frags, unpack('B', loader[0xA3:0xA4])[0])

    # Fix general data dir stuff
    new_pe = fix_data_dirs(pe, new_pe, frags, args.exports, args.resources)

    if args.imports:
        unknown_imp_struct_rva = unpack('<I', loader[0x107:0x10b])[0]
        new_pe = fix_imports(pe, new_pe, unknown_imp_struct_rva)

    # It's ugly, I know but uhh - look; the Petite loader itself writes a relative JMP to some arbitrary point (loader+0x282) to get to the OEP
    # To calculate the target you gotta add the section VA and offset from the start of the section, 0x1A being the offset from the Petite section
    # start to the point where the written JMP is, 5 being the length of the instruction, so all in all it correctly gets the OEP (pray it doesn't break)
    oep_rva = unpack('<i', loader[0x282:0x286])[0] + pe.sections[2].virtual_address + 0x1A + 5

    print (f"Setting EP to OEP: {oep_rva:#x}")
    new_pe.optional_header.addressof_entrypoint = oep_rva

    if args.relocs:
        new_pe = fix_relocations(pe, new_pe, frags)

    output_name = args.file[:args.file.rindex('.')] + '_unpacked' + args.file[args.file.rindex('.'):]

    print (f"Unpacked! Changes written to {output_name}")

    new_pe.write(output_name)

if __name__ == '__main__':
    main()
