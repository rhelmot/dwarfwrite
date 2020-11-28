from elftools.dwarf import enums
from collections import defaultdict

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
    def function_get_parameters(self, handler):
        return []
    def function_get_return_type(self, handler):
        return None
    def function_get_name(self, handler):
        return None
    def function_get_addr(self, handler):
        return None
    def function_get_end_addr(self, handler):
        return None
    def parameter_get_name(self, handler):
        return None
    def parameter_get_type(self, handler):
        return None
    def variable_get_name(self, handler):
        return None
    def variable_get_type(self, handler):
        return None
    def variable_get_addr(self, handler):
        return None
    def type_ptr_of(self, handler):
        return None
    def type_const_of(self, handler):
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
    def type_array_of(self, handler):
        return None
    def type_array_size(self, handler):
        return None
    def type_basic_name(self, handler):
        return None
    def type_basic_encoding(self, handler):
        return None
    def type_basic_size(self, handler):
        return None

    def run(self):
        result = []
        for unit in self.root_get_units():
            unit_result = {
                "tag": enums.ENUM_DW_TAG['DW_TAG_compile_unit'],
                enums.ENUM_DW_AT['DW_AT_name']: self.unit_get_filename(unit),
                enums.ENUM_DW_AT['DW_AT_language']: self.unit_get_language(unit),
                "children": [],
            }
            self.current_unit = unit_result
            self.type_id_cache = {}
            self.type_cache = {}

            for variable in self.unit_get_variables(unit):
                variable_result = {
                    "tag": enums.ENUM_DW_TAG['DW_TAG_variable'],
                    enums.ENUM_DW_AT['DW_AT_name']: self.variable_get_name(variable),
                    enums.ENUM_DW_AT['DW_AT_location']: self.variable_get_addr(variable),  # NOT address-wrapped? that doesn't make any sense
                    enums.ENUM_DW_AT['DW_AT_type']: self.process_type(self.variable_get_type(variable)),
                }
                unit_result['children'].append(variable_result)


            for func in self.unit_get_functions(unit):
                func_result = {
                    "tag": enums.ENUM_DW_TAG['DW_TAG_subprogram'],
                    enums.ENUM_DW_AT['DW_AT_name']: self.function_get_name(func),
                    enums.ENUM_DW_AT['DW_AT_low_pc']: self.function_get_addr(func),
                    enums.ENUM_DW_AT['DW_AT_high_pc']: self.function_get_end_addr(func),
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
                unit_result['children'].append(func_result)

            result.append(unit_result)

        return result

    def process_type(self, ty):
        if ty is None:
            return None
        if id(ty) in self.type_id_cache:
            return self.type_id_cache[id(ty)]
        if ty in self.type_cache:
            return self.type_cache[ty]

        result = self._process_type(ty)

        self.type_id_cache[id(ty)] = result
        self.type_cache[ty] = result
        self.current_unit["children"].insert(0, result)
        return result

    def _process_type(self, ty):
        sub = self.type_ptr_of(ty)
        if sub is not None:
            return {
                "tag": enums.ENUM_DW_TAG['DW_TAG_pointer_type'],
                enums.ENUM_DW_AT['DW_AT_type']: self.process_type(sub)
            }
        sub = self.type_const_of(ty)
        if sub is not None:
            return {
                "tag": enums.ENUM_DW_TAG['DW_TAG_const_type'],
                enums.ENUM_DW_AT['DW_AT_type']: self.process_type(sub)
            }
        sub = self.type_array_of(ty)
        if sub is not None:
            return {
                "tag": enums.ENUM_DW_TAG['DW_TAG_array_type'],
                "children": [
                    {
                        "tag": enums.ENUM_DW_TAG['DW_TAG_subrange_type'],
                        enums.ENUM_DW_AT['DW_AT_type']: self.process_type(sub)
                    }
                ]
            }
        name = self.type_struct_name(ty)
        if name is not None:
            result = {
                "tag": enums.ENUM_DW_TAG['DW_TAG_structure_type'],
                enums.ENUM_DW_AT['DW_AT_name']: name,
                enums.ENUM_DW_AT['DW_AT_byte_size']: self.type_struct_size(ty),
                "children": []
            }
            for member in self.type_struct_members(ty):
                result_member = {
                    "tag": enums.ENUM_DW_TAG['DW_TAG_member'],
                    enums.ENUM_DW_AT['DW_AT_name']: self.type_struct_member_name(member),
                    enums.ENUM_DW_AT['DW_AT_type']: self.process_type(self.type_struct_member_type(member)),
                    enums.ENUM_DW_AT['DW_AT_data_member_location']: self.type_struct_member_offset(member)
                }
                result["children"].append(result_member)
            return result
        name = self.type_basic_name(ty)
        if name is not None:
            return {
                "tag": enums.ENUM_DW_TAG['DW_TAG_base_type'],
                enums.ENUM_DW_AT['DW_AT_name']: name,
                enums.ENUM_DW_AT['DW_AT_byte_size']: self.type_basic_size(ty),
                enums.ENUM_DW_AT['DW_AT_encoding']: self.type_basic_encoding(ty),
            }

        raise TypeError("Could not identify %s as any type" % ty)
