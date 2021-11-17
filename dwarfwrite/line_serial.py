import struct
import typing
import copy
import os

from elftools.dwarf.lineprogram import LineState
from elftools.dwarf import constants

from . import serial

SECTION_VERSION = 4

def serialize_states(arch, states: typing.List[LineState]):
    # step 0: assemble constants and mappings
    endness = '<' if arch.memory_endness == 'Iend_LE' else '>'
    data = bytearray()
    minimum_instruction_length = 1
    max_ops_per_instruction = 1
    default_is_stmt = True
    line_base = 0
    line_range = 1
    opcode_base = 13

    filepaths = set(state.file for state in states)
    dirpaths = set(os.path.dirname(filename) for filename in filepaths)
    dirpaths.discard('')
    dirs = list(dirpaths)
    dirs_map = {dirpath: i + 1 for i, dirpath in enumerate(dirs)}
    dirs_map[''] = 0
    files = [(os.path.basename(filepath), dirs_map[os.path.dirname(filepath)], 0, 0) for filepath in filepaths]
    files_map = {filepath: i + 1 for i, filepath in enumerate(filepaths)}

    # step 1: header
    data.extend(struct.pack(
        endness + 'IHIBB?bBB',
        0,
        SECTION_VERSION,
        0,
        minimum_instruction_length,
        max_ops_per_instruction,
        default_is_stmt,
        line_base,
        line_range,
        opcode_base,
    ))
    data.extend(bytes([0, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 1]))  # standard opcode lengths
    for dirpath in dirs:
        data.extend(dirpath.encode())
        data.append(0)
    data.append(0)
    for (filename, dir_idx, mtime, length) in files:
        data.extend(filename.encode())
        data.append(0)
        data.extend(serial._Serializer.encode_leb128(dir_idx))
        data.extend(serial._Serializer.encode_leb128(mtime))
        data.extend(serial._Serializer.encode_leb128(length))
    data.append(0)
    struct.pack_into(endness + 'I', data, 6, len(data) - 10)

    prev_state = LineState(default_is_stmt)
    for target_state in states:
        # step 2: compute diff between states
        # TODO use special opcodes for compression
        if prev_state.address != target_state.address:
            if target_state.address < prev_state.address:
                data.append(0)
                subdata = bytearray()
                subdata.extend(serial._Serializer.encode_leb128(constants.DW_LNE_set_address))
                subdata.extend(serial._Serializer.encode_leb128(target_state.address))
                data.extend(serial._Serializer.encode_leb128(len(subdata)))
                data.extend(subdata)
            else:
                data.append(constants.DW_LNS_advance_pc)
                data.extend(serial._Serializer.encode_leb128(target_state.address - prev_state.address))
            prev_state.address = target_state.address
        if prev_state.file != target_state.file:
            data.append(constants.DW_LNS_set_file)
            data.extend(serial._Serializer.encode_leb128(files_map[target_state.file]))
            prev_state.file = target_state.file
        if prev_state.line != target_state.line:
            data.append(constants.DW_LNS_advance_line)
            data.extend(serial._Serializer.encode_leb128(target_state.line - prev_state.line))
            prev_state.line = target_state.line
        if prev_state.column != target_state.column:
            data.append(constants.DW_LNS_set_column)
            data.extend(serial._Serializer.encode_leb128(target_state.column))
            prev_state.column = target_state.column
        if prev_state.is_stmt != target_state.is_stmt:
            data.append(constants.DW_LNS_negate_stmt)
            prev_state.is_stmt = not prev_state.is_stmt
            assert prev_state.is_stmt == target_state.is_stmt
        if prev_state.basic_block != target_state.basic_block:
            data.append(constants.DW_LNS_set_basic_block)
            prev_state.basic_block = True
            assert prev_state.basic_block == target_state.basic_block
        if prev_state.prologue_end != target_state.prologue_end:
            data.append(constants.DW_LNS_set_prologue_end)
            prev_state.prologue_end = True
            assert prev_state.prologue_end == target_state.prologue_end
        if prev_state.epilogue_begin != target_state.epilogue_begin:
            data.append(constants.DW_LNS_set_epilogue_begin)
            prev_state.epilogue_begin = True
            assert prev_state.epilogue_begin == target_state.epilogue_begin
        if prev_state.isa != target_state.isa:
            data.append(constants.DW_LNS_set_isa)
            data.extend(serial._Serializer.encode_leb128(target_state.isa))
            prev_state.isa = target_state.isa
        if prev_state.discriminator != target_state.discriminator:
            data.append(0)
            subdata = bytearray()
            subdata.append(constants.DW_LNE_set_discriminator)
            subdata.extend(serial._Serializer.encode_leb128(target_state.discriminator))
            data.extend(serial._Serializer.encode_leb128(len(subdata)))
            data.extend(subdata)
            prev_state.discriminator = target_state.discriminator

        # step 3: now prev_state == target_state. emit and reset.
        if target_state.end_sequence:
            data.append(0)
            data.extend(serial._Serializer.encode_leb128(1))
            data.append(constants.DW_LNE_end_sequence)
            prev_state = LineState(default_is_stmt)
        else:
            data.append(constants.DW_LNS_copy)
            prev_state.discriminator = 0
            prev_state.basic_block = False
            prev_state.prologue_end = False
            prev_state.epilogue_begin = False

    # step n: fixup length field
    struct.pack_into(endness + 'I', data, 0, len(data) - 4)
    return data
