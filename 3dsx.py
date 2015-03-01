import idaapi
from idc import *
import struct

_3DSX_SIGNATURE     = "3DSX"
_3DSX_FORMAT_NAME   = "3DSX (homebrew applications on the 3DS)"
CN_3DSX_LOADADR     = 0x00108000
# -----------------------------------------------------------------------
def accept_file(li, n):
    """
    Check if the file is of supported format

    @param li: a file-like object which can be used to access the input data
    @param n : format number. The function will be called with incrementing 
               number until it returns zero
    @return: 0 - no more supported formats
             string "name" - format name to display in the chooser dialog
             dictionary { 'format': "name", 'options': integer }
               options: should be 1, possibly ORed with ACCEPT_FIRST (0x8000)
               to indicate preferred format
    """

    # we support only one format per file
    if n > 0:
        return 0

    # check the 3DSX signature
    li.seek(0)
    if li.read(4) == _3DSX_SIGNATURE:
        # accept the file
        return _3DSX_FORMAT_NAME
    
    # unrecognized format
    return 0

# -----------------------------------------------------------------------
# https://github.com/smealum/ninjhax/blob/0e45db1ecbe603374de56766cbfae9e7bd37c216/ro_command_handler/source/3dsx.c
# https://github.com/smealum/ninjhax/blob/0e45db1ecbe603374de56766cbfae9e7bd37c216/ro_command_handler/source/3dsx.h
def load_file(li, neflags, format):
    
    """
    Load the file into database

    @param li: a file-like object which can be used to access the input data
    @param neflags: options selected by the user, see loader.hpp
    @return: 0-failure, 1-ok
    """

    if format == _3DSX_FORMAT_NAME:
    
        idaapi.set_processor_type("arm", SETPROC_ALL|SETPROC_FATAL)
        
        li.seek(0)

        (magic, header_size, reloc_header_size, format_ver, flags, code_seg_size, rodata_seg_size, data_seg_size, bss_seg_size) = struct.unpack("<IHHIIIIII", li.read(4*8))
        
        #print(hex(header_size))
        #print(hex(reloc_header_size))
        #print(hex(code_seg_size))
        #print(hex(rodata_seg_size))
        #print(hex(data_seg_size))
        #print(hex(bss_seg_size))
        
        #CODE SEGMENT
        seg1 = CN_3DSX_LOADADR
        seg1_size = (code_seg_size + 0xFFF) &(~0xFFF)
        file_offset = header_size + reloc_header_size*3
        
        AddSeg(seg1, seg1 + seg1_size, 0, 1, idaapi.saRelPara, idaapi.scPub)
        SetSegmentType(seg1, idaapi.SEG_CODE)
        RenameSeg(seg1, "CODE")        
        li.file2base(file_offset, seg1, seg1 + code_seg_size, 0)

        
        #RO_DATA SEGMENT
        seg2 = seg1 + seg1_size
        seg2_size = (rodata_seg_size + 0xFFF) &(~0xFFF)
        file_offset += code_seg_size
        
        AddSeg(seg2, seg2 + seg2_size, 0, 1, idaapi.saRelPara, idaapi.scPub)
        SetSegmentType(seg2, idaapi.SEG_DATA)
        RenameSeg(seg2, "RODATA")
        li.file2base(file_offset, seg2, seg2 + rodata_seg_size, 0)
        
        #DATA SEGMENT
        seg3 = seg2 + seg2_size
        seg3_size = (data_seg_size + 0xFFF) &(~0xFFF)
        file_offset += rodata_seg_size
        
        AddSeg(seg3, seg3 + seg3_size, 0, 1, idaapi.saRelPara, idaapi.scPub)
        SetSegmentType(seg3, idaapi.SEG_DATA)
        RenameSeg(seg3, "DATA")
        li.file2base(file_offset, seg3, seg3 + (data_seg_size - bss_seg_size), 0)
        
        #relocations
        relocs_ptr = file_offset + (data_seg_size - bss_seg_size)
        
        segments = [seg1, seg2, seg3]
        
        for rel_table in range(3):
        
            li.seek(header_size + rel_table * 8)
            (abs_count, rel_count) = struct.unpack("<II", li.read(4*2))
        
            li.seek(relocs_ptr)
            relocs_ptr = relocs_ptr + (abs_count * 4 + rel_count * 4)

            pos = segments[rel_table]
            
            #absolute relocations
            for i in range(abs_count):
                (skip, patches) = struct.unpack("<HH", li.read(2*2))
                
                pos += skip * 4
                for x in range(patches):
                    
                    addr = Dword(pos)
                    if addr < seg1_size:
                        addr = seg1 + addr
                    elif addr < (seg1_size + seg2_size):
                        addr = seg2 + addr - seg1_size
                    else:
                        addr = seg3 + addr - (seg1_size + seg2_size)

                    PatchDword(pos, addr)
                    SetFixup(pos, idaapi.FIXUP_OFF32 or idaapi.FIXUP_CREATED, 0, addr, 0)
                    pos += 4
                    
            # cross-segment relative relocations
            for i in range(rel_count):
                (skip, patches) = struct.unpack("<HH", li.read(2*2))
                
                pos += skip * 4
                for x in range(patches):
                    
                    addr = Dword(pos)
                    if addr < seg1_size:
                        addr = seg1 + addr
                    elif addr < (seg1_size + seg2_size):
                        addr = seg2 + addr - seg1_size
                    else:
                        addr = seg3 + addr - (seg1_size + seg2_size)
                    
                    PatchDword(pos, addr - pos)
                    SetFixup(pos, idaapi.FIXUP_OFF32 or idaapi.FIXUP_CREATED, 0, addr - pos, 0)
                    pos += 4                    
        
        idaapi.add_entry(CN_3DSX_LOADADR, CN_3DSX_LOADADR, "start", 1)
        idaapi.analyze_area(seg1, seg1 + seg1_size)
        
        print "Load OK"
        return 1
    
    return 0
# -----------------------------------------------------------------------
