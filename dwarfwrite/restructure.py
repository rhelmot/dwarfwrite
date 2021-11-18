import os
import logging

from elftools.dwarf.compileunit import CompileUnit
from elftools.dwarf.die import DIE, AttributeValue
from elftools.elf.elffile import ELFFile
from elftools.dwarf.dwarf_expr import DWARFExprParser
from elftools.dwarf import locationlists

from cle.backends.elf import ELF

from .structure import DWARFStructurer
from .serial import Address, LocationEntry, serialize, RangeEntry
from .elf import dump_elf

l = logging.getLogger(__name__)

VOID = object()

class ReStructurer(DWARFStructurer):
    def __init__(self, fp, **kwargs):
        super().__init__()

        self.elf = ELFFile(fp)
        self.dwarf = self.elf.get_dwarf_info()
        self.expr_parser = DWARFExprParser(self.dwarf.structs)
        self.loc_parser = self.dwarf.location_lists()
        self.arch = ELF.extract_arch(self.elf)

    @classmethod
    def rewrite_dwarf(cls, in_path, out_path, **kwargs):
        with open(in_path, 'rb') as fp:
            structurer = cls(fp, **kwargs)
            structure = structurer.run()

        serial = serialize(structure, structurer.arch)
        dump_elf(serial, structurer.arch, out_path, in_path)

    def get_attribute(self, die: DIE, name):
        attr = die.attributes.get(name, None)
        if attr is None:
            return None
        result = attr.value
        if attr.form == 'DW_FORM_exprloc':
            result = self.expr_parser.parse_expr(result)
        elif name == 'DW_AT_location' and attr.form == 'DW_FORM_sec_offset':
            base_addr = 0
            low_pc = die.cu.get_top_DIE().attributes.get('DW_AT_low_pc', None)
            if low_pc is not None:
                base_addr = low_pc.value
            loc_list = self.loc_parser.get_location_list_at_offset(result)
            result = []
            for item in loc_list:
                if type(item) is locationlists.LocationEntry:
                    result.append(LocationEntry(
                        base_addr + item.begin_offset,
                        base_addr + item.end_offset,
                        self.expr_parser.parse_expr(item.loc_expr)))
                elif type(item) is locationlists.BaseAddressEntry:
                    base_addr = item.base_address
                else:
                    raise TypeError("What kind of loclist entry is this?")
        elif attr.form == 'DW_FORM_addr':
            result = Address(result)
        elif name == 'DW_AT_type':
            result = die.cu.get_DIE_from_refaddr(result + die.cu.cu_offset)
        return result

    @staticmethod
    def filter_children(die, tag):
        for child in die.iter_children():
            if child.tag == tag:
                yield child

    def get_expression_attribute(self, die, tag):
        expr_list = self.get_attribute(die, tag)
        if expr_list is None:
            return None
        return self.expr_parser.parse_expr(expr_list)

    def get_ranges(self, die):
        ranges = die.attributes.get('DW_AT_ranges', None)
        if ranges is not None:
            return self.dwarf.range_lists().get_range_list_at_offset(ranges.value)
        low_pc = die.attributes.get('DW_AT_low_pc', None)
        high_pc = die.attributes.get('DW_AT_high_pc', None)
        if low_pc is not None and high_pc is not None:
            # TODO base addresses???
            fixed_high_pc = high_pc.value if high_pc.form == 'DW_FORM_addr' else low_pc.value + high_pc.value
            return [RangeEntry(low_pc.value, fixed_high_pc)]
        if low_pc is not None or high_pc is not None:
            raise Exception('Strange ranges - one but not both of low_pc + high_pc')
        return []

    def root_get_units(self):
        return list(self.dwarf.iter_CUs())

    def unit_get_filename(self, handler: CompileUnit):
        return self.get_attribute(handler.get_top_DIE(), 'DW_AT_name')

    def unit_get_language(self, handler: CompileUnit):
        return self.get_attribute(handler.get_top_DIE(), 'DW_AT_language')

    def unit_get_variables(self, handler: CompileUnit):
        return self.filter_children(handler.get_top_DIE(), 'DW_TAG_variable')

    def unit_get_functions(self, handler: CompileUnit):
        return self.filter_children(handler.get_top_DIE(), 'DW_TAG_subprogram')

    def unit_get_ranges(self, handler):
        return self.get_ranges(handler.get_top_DIE())

    def unit_get_comp_dir(self, handler: CompileUnit):
        return self.get_attribute(handler.get_top_DIE(), 'DW_AT_comp_dir')

    def unit_get_lines(self, handler: CompileUnit):
        lineprog = self.dwarf.line_program_for_CU(handler)
        if lineprog is None:
            return None

        entries = lineprog.get_entries()
        states = [entry.state for entry in entries if entry.state is not None]
        if not states:
            return None

        file_cache = {}
        for state in states:
            if state.file in file_cache:
                filename = file_cache[state.file]
            else:
                file_entry = lineprog.header['file_entry'][state.file - 1]
                if file_entry["dir_index"] == 0:
                    filename = file_entry.name.decode()
                else:
                    filename = os.path.join(
                        lineprog.header["include_directory"][file_entry["dir_index"] - 1].decode(),
                        file_entry.name.decode())
                file_cache[state.file] = filename

            state.file = filename

        return states

    def unit_get_producer(self, handler: CompileUnit):
        result = self.get_attribute(handler.get_top_DIE(), 'DW_AT_producer')
        if result is None:
            result = super().unit_get_producer(handler)
        return result

    def function_get_ranges(self, handler):
        return self.get_ranges(handler)

    def function_get_name(self, handler: DIE):
        return self.get_attribute(handler, 'DW_AT_name')

    def function_get_return_type(self, handler: DIE):
        return self.get_attribute(handler, 'DW_AT_type')

    def function_get_noreturn(self, handler: DIE):
        return handler.attributes.get('DW_AT_noreturn', False)

    def function_get_inline(self, handler: DIE):
        return self.get_attribute(handler, 'DW_AT_inline')

    def function_get_abstract_origin(self, handler: DIE):
        r = self.get_attribute(handler, 'DW_AT_abstract_origin')
        if r is None:
            return None
        assert type(r) is int
        return handler.cu.get_DIE_from_refaddr(handler.cu.cu_offset + r)

    def function_get_parameters(self, handler: DIE):
        return self.filter_children(handler, 'DW_TAG_formal_parameter')

    def function_get_variables(self, handler):
        return self.filter_children(handler, 'DW_TAG_variable')

    def function_get_lexicalblocks(self, handler):
        return self.filter_children(handler, 'DW_TAG_lexical_block')

    def lexicalblock_get_ranges(self, handler):
        return self.get_ranges(handler)

    def lexicalblock_get_variables(self, handler):
        return self.filter_children(handler, 'DW_TAG_variable')

    def lexicalblock_get_lexicalblocks(self, handler):
        return self.filter_children(handler, 'DW_TAG_lexical_block')

    def parameter_get_name(self, handler):
        return self.get_attribute(handler, 'DW_AT_name')

    def parameter_get_type(self, handler):
        return self.get_attribute(handler, 'DW_AT_type')

    def variable_get_location(self, handler):
        return self.get_attribute(handler, 'DW_AT_location')

    def variable_get_name(self, handler):
        return self.get_attribute(handler, 'DW_AT_name')

    def variable_get_type(self, handler):
        return self.get_attribute(handler, 'DW_AT_type')

    def type_ptr_of(self, handler: DIE):
        if getattr(handler, 'tag', None) == 'DW_TAG_pointer_type':
            subty = self.get_attribute(handler, 'DW_AT_type')
            if subty is None:
                return VOID
            return subty
        return None

    def type_const_of(self, handler):
        if getattr(handler, 'tag', None) == 'DW_TAG_const_type':
            subty = self.get_attribute(handler, 'DW_AT_type')
            if subty is None:
                return VOID
            return subty
        return None

    def type_volatile_of(self, handler):
        if getattr(handler, 'tag', None) == 'DW_TAG_volatile_type':
            subty = self.get_attribute(handler, 'DW_AT_type')
            if subty is None:
                return VOID
            return subty
        return None

    def type_array_of(self, handler):
        if getattr(handler, 'tag', None) == 'DW_TAG_array_type':
            return self.get_attribute(handler, 'DW_AT_type')
        return None

    def type_array_size(self, handler):
        if getattr(handler, 'tag', None) == 'DW_TAG_array_type':
            children = list(self.filter_children(handler, 'DW_TAG_subrange_type'))
            if children:
                return self.get_attribute(children[0], 'DW_AT_count')
        return None

    def type_struct_name(self, handler):
        if getattr(handler, 'tag', None) == 'DW_TAG_structure_type':
            return self.get_attribute(handler, 'DW_AT_name')
        return None

    def type_struct_size(self, handler):
        if getattr(handler, 'tag', None) == 'DW_TAG_structure_type':
            return self.get_attribute(handler, 'DW_AT_byte_size')
        return None

    def type_struct_members(self, handler):
        if getattr(handler, 'tag', None) == 'DW_TAG_structure_type':
            return self.filter_children(handler, 'DW_TAG_member')
        return None

    def type_struct_member_name(self, handler):
        return self.get_attribute(handler, 'DW_AT_name')

    def type_struct_member_type(self, handler):
        return self.get_attribute(handler, 'DW_AT_type')

    def type_struct_member_offset(self, handler):
        return self.get_attribute(handler, 'DW_AT_data_member_location')

    def type_union_name(self, handler):
        if getattr(handler, 'tag', None) == 'DW_TAG_union_type':
            return self.get_attribute(handler, 'DW_AT_name')
        return None

    def type_union_size(self, handler):
        if getattr(handler, 'tag', None) == 'DW_TAG_union_type':
            return self.get_attribute(handler, 'DW_AT_byte_size')
        return None

    def type_union_members(self, handler):
        if getattr(handler, 'tag', None) == 'DW_TAG_union_type':
            return self.filter_children(handler, 'DW_TAG_member')
        return None

    def type_union_member_name(self, handler):
        return self.get_attribute(handler, 'DW_AT_name')

    def type_union_member_type(self, handler):
        return self.get_attribute(handler, 'DW_AT_type')

    def type_union_member_offset(self, handler):
        return self.get_attribute(handler, 'DW_AT_data_member_location')

    def type_enum_name(self, handler):
        if getattr(handler, 'tag', None) == 'DW_TAG_enumeration_type':
            return self.get_attribute(handler, 'DW_AT_name')
        return None

    def type_enum_type(self, handler):
        if getattr(handler, 'tag', None) == 'DW_TAG_enumeration_type':
            return self.get_attribute(handler, 'DW_AT_type')
        return None

    def type_enum_size(self, handler):
        if getattr(handler, 'tag', None) == 'DW_TAG_enumeration_type':
            return self.get_attribute(handler, 'DW_AT_byte_size')
        return None

    def type_enum_members(self, handler):
        return self.filter_children(handler, "DW_TAG_enumerator")

    def type_enum_member_name(self, handler):
        return self.get_attribute(handler, "DW_AT_name")

    def type_enum_member_value(self, handler):
        return self.get_attribute(handler, "DW_AT_const_value")

    def type_func_args(self, handler):
        if getattr(handler, 'tag', None) == "DW_TAG_subroutine_type":
            return self.filter_children(handler, "DW_TAG_formal_parameter")
        return None

    def type_func_arg_type(self, handler):
        return self.get_attribute(handler, "DW_AT_type")

    def type_typedef_name(self, handler):
        if getattr(handler, 'tag', None) == 'DW_TAG_typedef':
            return self.get_attribute(handler, 'DW_AT_name')
        return None

    def type_typedef_of(self, handler):
        if getattr(handler, 'tag', None) == 'DW_TAG_typedef':
            return self.get_attribute(handler, 'DW_AT_type')
        return None

    def type_basic_name(self, handler):
        if getattr(handler, 'tag', None) == 'DW_TAG_base_type':
            return self.get_attribute(handler, 'DW_AT_name')
        return None

    def type_basic_encoding(self, handler):
        if getattr(handler, 'tag', None) == 'DW_TAG_base_type':
            return self.get_attribute(handler, 'DW_AT_encoding')
        return None

    def type_basic_size(self, handler):
        if getattr(handler, 'tag', None) == 'DW_TAG_base_type':
            return self.get_attribute(handler, 'DW_AT_byte_size')
        return None

    def type_is_void(self, handler):
        return handler is VOID
