from elftools.dwarf import enums
from collections import defaultdict

from .serial import VALUE_PRESENT, Address
from . import __version__

class DWARFStructurer:
    def __init__(self):
        self.handlers = defaultdict(lambda: lambda *a, **kw: None)

        self.current_unit = None
        self.type_id_cache = {}
        self.type_cache = {}

    def root_get_units(self):
        return []
    def unit_get_filename(self, handler):
        return None
    def unit_get_functions(self, handler):
        return []
    def unit_get_variables(self, handler):
        return []
    def unit_get_language(self, handler):
        return None
    def unit_get_ranges(self, handler):
        return []
    def unit_get_lines(self, handler):
        return None
    def unit_get_comp_dir(self, handler):
        return None
    def unit_get_producer(self, handler):
        return 'dwarfwrite ' + '.'.join(str(v) for v in __version__)
    def function_get_return_type(self, handler):
        return None
    def function_get_name(self, handler):
        return None
    def function_get_ranges(self, handler):
        return []
    def function_get_noreturn(self, handler):
        return False
    def function_get_parameters(self, handler):
        return []
    def function_get_variables(self, handler):
        return []
    def function_get_lexicalblocks(self, handler):
        return []
    def lexicalblock_get_ranges(self, handler):
        return []
    def lexicalblock_get_variables(self, handler):
        return []
    def lexicalblock_get_lexicalblocks(self, handler):
        return []
    def parameter_get_name(self, handler):
        return None
    def parameter_get_type(self, handler):
        return None
    def variable_get_name(self, handler):
        return None
    def variable_get_type(self, handler):
        return None
    def variable_get_location(self, handler):
        return None
    def type_ptr_of(self, handler):
        return None
    def type_const_of(self, handler):
        return None
    def type_volatile_of(self, handler):
        return None
    def type_struct_name(self, handler):
        return None
    def type_struct_members(self, handler):
        return []
    def type_struct_member_name(self, handler):
        return None
    def type_struct_member_type(self, handler):
        return None
    def type_struct_member_offset(self, handler):
        return None
    def type_struct_size(self, handler):
        return None
    def type_union_name(self, handler):
        return None
    def type_union_members(self, handler):
        return []
    def type_union_member_name(self, handler):
        return None
    def type_union_member_type(self, handler):
        return None
    def type_union_member_offset(self, handler):
        return None
    def type_union_size(self, handler):
        return None
    def type_enum_name(self, handler):
        return None
    def type_enum_type(self, handler):
        return None
    def type_enum_size(self, handler):
        return None
    def type_enum_members(self, handler):
        return []
    def type_enum_member_name(self, handler):
        return None
    def type_enum_member_value(self, handler):
        return None
    def type_array_of(self, handler):
        return None
    def type_array_size(self, handler):
        return None
    def type_func_args(self, handler):
        return None
    def type_func_arg_type(self, handler):
        return None
    def type_typedef_of(self, handler):
        return None
    def type_typedef_name(self, handler):
        return None
    def type_basic_name(self, handler):
        return None
    def type_basic_encoding(self, handler):
        return None
    def type_basic_size(self, handler):
        return None
    def type_is_void(self, handler):
        return False

    def run(self):
        result = []
        for unit in self.root_get_units():
            unit_result = {
                "tag": enums.ENUM_DW_TAG['DW_TAG_compile_unit'],
                enums.ENUM_DW_AT['DW_AT_name']: self.unit_get_filename(unit),
                enums.ENUM_DW_AT['DW_AT_language']: self.unit_get_language(unit),
                enums.ENUM_DW_AT['DW_AT_comp_dir']: self.unit_get_comp_dir(unit),
                enums.ENUM_DW_AT['DW_AT_stmt_list']: self.unit_get_lines(unit),
                enums.ENUM_DW_AT['DW_AT_producer']: self.unit_get_producer(unit),
                "children": [],
            }
            unit_result.update(self.process_ranges(self.unit_get_ranges(unit)))
            if enums.ENUM_DW_AT['DW_AT_low_pc'] not in unit_result:
                # TODO ??????????
                unit_result[enums.ENUM_DW_AT['DW_AT_low_pc']] = Address(0)
            self.current_unit = unit_result
            self.type_id_cache = {}
            self.type_cache = {}

            unit_result['children'].extend(self.process_variable(var) for var in self.unit_get_variables(unit))


            for func in self.unit_get_functions(unit):
                func_result = {
                    "tag": enums.ENUM_DW_TAG['DW_TAG_subprogram'],
                    enums.ENUM_DW_AT['DW_AT_name']: self.function_get_name(func),
                    enums.ENUM_DW_AT['DW_AT_type']: self.process_type(self.function_get_return_type(func)),
                    "children": [
                        {
                            "tag": enums.ENUM_DW_TAG['DW_TAG_formal_parameter'],
                            enums.ENUM_DW_AT['DW_AT_name']: self.parameter_get_name(func_param),
                            enums.ENUM_DW_AT['DW_AT_type']: self.process_type(self.parameter_get_type(func_param)),
                        }
                        for func_param in self.function_get_parameters(func)
                    ]
                }
                func_result.update(self.process_ranges(self.function_get_ranges(func)))
                if self.function_get_noreturn(func):
                    func_result[enums.ENUM_DW_AT['DW_AT_noreturn']] = VALUE_PRESENT
                func_result['children'].extend(self.process_variable(func_var)
                                               for func_var in self.function_get_variables(func))
                func_result['children'].extend(self.process_lexical_block(block)
                                               for block in self.function_get_lexicalblocks(func))

                unit_result['children'].append(func_result)

            result.append(unit_result)

        return result

    def process_variable(self, var):
        return {
            "tag": enums.ENUM_DW_TAG['DW_TAG_variable'],
            enums.ENUM_DW_AT['DW_AT_name']: self.variable_get_name(var),
            enums.ENUM_DW_AT['DW_AT_location']: self.variable_get_location(var),
            enums.ENUM_DW_AT['DW_AT_type']: self.process_type(self.variable_get_type(var)),
        }

    def process_lexical_block(self, block):
        result = {
            'tag': enums.ENUM_DW_TAG['DW_TAG_lexical_block'],
            'children': [],
        }
        result.update(self.process_ranges(self.lexicalblock_get_ranges(block)))
        result['children'].extend(self.process_variable(var) for var in self.lexicalblock_get_variables(block))
        result['children'].extend(self.process_lexical_block(var) for var in self.lexicalblock_get_lexicalblocks(block))
        return result

    def process_ranges(self, ranges):
        result = {}
        if len(ranges) == 1:
            result[enums.ENUM_DW_AT['DW_AT_low_pc']] = Address(ranges[0].begin_offset)
            result[enums.ENUM_DW_AT['DW_AT_high_pc']] = int(ranges[0].end_offset - ranges[0].begin_offset)
        elif len(ranges) > 1:
            result[enums.ENUM_DW_AT['DW_AT_ranges']] = ranges
        return result

    def process_type(self, ty):
        if self.type_is_void(ty):
            return None
        if ty is None:
            return None
        if id(ty) in self.type_id_cache:
            return self.type_id_cache[id(ty)]
        if ty in self.type_cache:
            return self.type_cache[ty]

        result = {}
        self.type_id_cache[id(ty)] = result
        self.type_cache[ty] = result
        self.current_unit["children"].insert(0, result)

        self._process_type(ty, result)
        return result

    def _process_type(self, ty, result):
        sub = self.type_ptr_of(ty)
        if sub is not None:
            result.update({
                "tag": enums.ENUM_DW_TAG['DW_TAG_pointer_type'],
                enums.ENUM_DW_AT['DW_AT_type']: self.process_type(sub)
            })
            return
        sub = self.type_const_of(ty)
        if sub is not None:
            result.update({
                "tag": enums.ENUM_DW_TAG['DW_TAG_const_type'],
                enums.ENUM_DW_AT['DW_AT_type']: self.process_type(sub)
            })
            return
        sub = self.type_volatile_of(ty)
        if sub is not None:
            result.update({
                "tag": enums.ENUM_DW_TAG['DW_TAG_volatile_type'],
                enums.ENUM_DW_AT['DW_AT_type']: self.process_type(sub)
            })
            return
        sub = self.type_array_of(ty)
        if sub is not None:
            result.update({
                "tag": enums.ENUM_DW_TAG['DW_TAG_array_type'],
                enums.ENUM_DW_AT['DW_AT_type']: self.process_type(sub),
                "children": [
                    {
                        "tag": enums.ENUM_DW_TAG['DW_TAG_subrange_type'],
                        enums.ENUM_DW_AT['DW_AT_count']: self.type_array_size(ty),
                    }
                ]
            })
            return
        name = self.type_struct_name(ty)
        size = self.type_struct_size(ty)
        if size is not None or name is not None:
            result.update({
                "tag": enums.ENUM_DW_TAG['DW_TAG_structure_type'],
                enums.ENUM_DW_AT['DW_AT_name']: name,
                enums.ENUM_DW_AT['DW_AT_byte_size']: size,
                enums.ENUM_DW_AT['DW_AT_declaration']: VALUE_PRESENT if size is None else None,
                "children": []
            })
            for member in self.type_struct_members(ty):
                result_member = {
                    "tag": enums.ENUM_DW_TAG['DW_TAG_member'],
                    enums.ENUM_DW_AT['DW_AT_name']: self.type_struct_member_name(member),
                    enums.ENUM_DW_AT['DW_AT_type']: self.process_type(self.type_struct_member_type(member)),
                    enums.ENUM_DW_AT['DW_AT_data_member_location']: self.type_struct_member_offset(member)
                }
                result["children"].append(result_member)
            return
        name = self.type_union_name(ty)
        size = self.type_union_size(ty)
        if size is not None or name is not None:
            result.update({
                "tag": enums.ENUM_DW_TAG['DW_TAG_union_type'],
                enums.ENUM_DW_AT['DW_AT_name']: name,
                enums.ENUM_DW_AT['DW_AT_byte_size']: size,
                enums.ENUM_DW_AT['DW_AT_declaration']: VALUE_PRESENT if size is None else None,
                "children": []
            })
            for member in self.type_union_members(ty):
                result_member = {
                    "tag": enums.ENUM_DW_TAG['DW_TAG_member'],
                    enums.ENUM_DW_AT['DW_AT_name']: self.type_union_member_name(member),
                    enums.ENUM_DW_AT['DW_AT_type']: self.process_type(self.type_union_member_type(member)),
                    enums.ENUM_DW_AT['DW_AT_data_member_location']: self.type_union_member_offset(member)
                }
                result["children"].append(result_member)
            return
        size = self.type_enum_size(ty)
        if size is not None:
            result.update({
                "tag": enums.ENUM_DW_TAG['DW_TAG_enumeration_type'],
                enums.ENUM_DW_AT['DW_AT_name']: self.type_enum_name(ty),
                enums.ENUM_DW_AT['DW_AT_byte_size']: size,
                "children": []
            })
            for member in self.type_enum_members(ty):
                result_member = {
                    "tag": enums.ENUM_DW_TAG['DW_TAG_enumerator'],
                    enums.ENUM_DW_AT['DW_AT_name']: self.type_enum_member_name(member),
                    enums.ENUM_DW_AT['DW_AT_const_value']: self.type_enum_member_value(member)
                }
                result["children"].append(result_member)
            return
        args = self.type_func_args(ty)
        if args is not None:
            result.update({
                "tag": enums.ENUM_DW_TAG['DW_TAG_subroutine_type'],
                enums.ENUM_DW_AT['DW_AT_prototyped']: VALUE_PRESENT,
                "children": [{
                    "tag": enums.ENUM_DW_TAG['DW_TAG_formal_parameter'],
                    enums.ENUM_DW_AT['DW_AT_type']: self.process_type(self.type_func_arg_type(subty)),
                } for subty in args]
            })
            return
        name = self.type_typedef_name(ty)
        if name is not None:
            result.update({
                "tag": enums.ENUM_DW_TAG['DW_TAG_typedef'],
                enums.ENUM_DW_AT['DW_AT_name']: name,
                enums.ENUM_DW_AT['DW_AT_type']: self.process_type(self.type_typedef_of(ty))
            })
            return
        name = self.type_basic_name(ty)
        if name is not None:
            result.update({
                "tag": enums.ENUM_DW_TAG['DW_TAG_base_type'],
                enums.ENUM_DW_AT['DW_AT_name']: name,
                enums.ENUM_DW_AT['DW_AT_byte_size']: self.type_basic_size(ty),
                enums.ENUM_DW_AT['DW_AT_encoding']: self.type_basic_encoding(ty),
            })
            return

        raise TypeError("Could not identify %s as any type" % ty)
