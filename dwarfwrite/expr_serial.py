import struct

from elftools.dwarf.dwarf_expr import DW_OP_name2opcode

from . import serial

ULEB128 = object()
SLEB128 = object()

class DWARFExprSerializer:
    """DWARF expression serializer.

    When initialized, requires structs to cache a dispatch table. After that,
    serialize_expr can be called repeatedly - it's stateless.
    """

    def __init__(self, arch):
        self._dispatch_table = _init_dispatch_table(arch)

    def serialize_expr(self, expr):
        """ Serializes a list of DWARFExprOp.
        """
        serialized = bytearray()

        for op in expr:
            serialized.append(op.op)
            arg_serializer = self._dispatch_table[op.op]
            serialized.extend(arg_serializer(op))

        return serialized


def _init_dispatch_table(arch):
    """Creates a dispatch table for parsing args of an op.

    Returns a dict mapping opcode to a function. The function accepts a stream
    and return a list of parsed arguments for the opcode from the stream;
    the stream is advanced by the function as needed.
    """
    table = {}
    def add(opcode_name, func):
        table[DW_OP_name2opcode[opcode_name]] = func

    def parse_noargs():
        return lambda stream: b''

    def parse_op_addr():
        return lambda stream: struct_parse(arch.struct_fmt(),
                                            stream.args[0])

    def parse_arg_struct(arg_struct):
        return lambda stream: struct_parse(arg_struct, stream.args[0])

    def parse_arg_struct2(arg1_struct, arg2_struct):
        return lambda stream: struct_parse(arg1_struct, stream.args[0]) + \
                               struct_parse(arg2_struct, stream.args[1])

    # ULEB128, then an expression of that length
    def parse_nestedexpr():
        def parse(stream):
            nested_expr_blob = DWARFExprSerializer(arch).serialize_expr(stream.args[0])
            size_blob = struct_parse(ULEB128, len(nested_expr_blob))
            return size_blob + nested_expr_blob
        return parse

    # ULEB128, then a blob of that size
    def parse_blob():
        def parse(stream):
            blob = bytearray(stream.args[0])
            return struct_parse(ULEB128, len(blob)) + blob
        return parse

    # ULEB128 with datatype DIE offset, then byte, then a blob of that size
    def parse_typedblob():
        def parse(stream):
            raise NotImplementedError("not yet supported")
        return parse
        #return lambda stream: [struct_parse(ULEB128, stream), read_blob(stream, struct_parse(arch.struct_fmt(size=1), stream))]

    add('DW_OP_addr', parse_op_addr())
    add('DW_OP_const1u', parse_arg_struct(arch.struct_fmt(size=1)))
    add('DW_OP_const1s', parse_arg_struct(arch.struct_fmt(size=1, signed=True)))
    add('DW_OP_const2u', parse_arg_struct(arch.struct_fmt(size=2)))
    add('DW_OP_const2s', parse_arg_struct(arch.struct_fmt(size=2, signed=True)))
    add('DW_OP_const4u', parse_arg_struct(arch.struct_fmt(size=4)))
    add('DW_OP_const4s', parse_arg_struct(arch.struct_fmt(size=4, signed=True)))
    add('DW_OP_const8u', parse_arg_struct(arch.struct_fmt(size=8)))
    add('DW_OP_const8s', parse_arg_struct(arch.struct_fmt(size=8, signed=True)))
    add('DW_OP_constu', parse_arg_struct(ULEB128))
    add('DW_OP_consts', parse_arg_struct(SLEB128))
    add('DW_OP_pick', parse_arg_struct(arch.struct_fmt(size=1)))
    add('DW_OP_plus_uconst', parse_arg_struct(ULEB128))
    add('DW_OP_bra', parse_arg_struct(arch.struct_fmt(size=2, signed=True)))
    add('DW_OP_skip', parse_arg_struct(arch.struct_fmt(size=2, signed=True)))

    for opname in [ 'DW_OP_deref', 'DW_OP_dup', 'DW_OP_drop', 'DW_OP_over',
                    'DW_OP_swap', 'DW_OP_swap', 'DW_OP_rot', 'DW_OP_xderef',
                    'DW_OP_abs', 'DW_OP_and', 'DW_OP_div', 'DW_OP_minus',
                    'DW_OP_mod', 'DW_OP_mul', 'DW_OP_neg', 'DW_OP_not',
                    'DW_OP_or', 'DW_OP_plus', 'DW_OP_shl', 'DW_OP_shr',
                    'DW_OP_shra', 'DW_OP_xor', 'DW_OP_eq', 'DW_OP_ge',
                    'DW_OP_gt', 'DW_OP_le', 'DW_OP_lt', 'DW_OP_ne', 'DW_OP_nop',
                    'DW_OP_push_object_address', 'DW_OP_form_tls_address',
                    'DW_OP_call_frame_cfa', 'DW_OP_stack_value',
                    'DW_OP_GNU_push_tls_address']:
        add(opname, parse_noargs())

    for n in range(0, 32):
        add('DW_OP_lit%s' % n, parse_noargs())
        add('DW_OP_reg%s' % n, parse_noargs())
        add('DW_OP_breg%s' % n, parse_arg_struct(SLEB128))

    add('DW_OP_fbreg', parse_arg_struct(SLEB128))
    add('DW_OP_regx', parse_arg_struct(ULEB128))
    add('DW_OP_bregx', parse_arg_struct2(ULEB128,
                                         SLEB128))
    add('DW_OP_piece', parse_arg_struct(ULEB128))
    add('DW_OP_bit_piece', parse_arg_struct2(ULEB128,
                                             ULEB128))
    add('DW_OP_deref_size', parse_arg_struct(arch.struct_fmt(size=1, signed=True)))
    add('DW_OP_xderef_size', parse_arg_struct(arch.struct_fmt(size=1, signed=True)))
    add('DW_OP_call2', parse_arg_struct(arch.struct_fmt(size=2)))
    add('DW_OP_call4', parse_arg_struct(arch.struct_fmt(size=4)))
    add('DW_OP_call_ref', parse_arg_struct(arch.struct_fmt()))
    add('DW_OP_implicit_value', parse_blob())
    add('DW_OP_GNU_entry_value', parse_nestedexpr())
    add('DW_OP_GNU_const_type', parse_typedblob())
    add('DW_OP_GNU_regval_type', parse_arg_struct2(ULEB128,
                                                   ULEB128))
    add('DW_OP_GNU_deref_type', parse_arg_struct2(arch.struct_fmt(size=1),
                                                  ULEB128))
    add('DW_OP_GNU_implicit_pointer', parse_arg_struct2(arch.struct_fmt(),
                                                        SLEB128))
    add('DW_OP_GNU_parameter_ref', parse_arg_struct(arch.struct_fmt()))
    add('DW_OP_GNU_convert', parse_arg_struct(ULEB128))

    return table

def struct_parse(fmt, data):
    if fmt in (ULEB128, SLEB128):
        return serial._Serializer.encode_leb128(data)
    return struct.pack(fmt, data)
