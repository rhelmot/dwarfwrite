import struct
from collections import namedtuple
import pprint

import archinfo

from elftools.dwarf import enums, dwarf_expr, lineprogram
from elftools.dwarf.ranges import RangeEntry, BaseAddressEntry

from .expr_serial import DWARFExprSerializer
from .line_serial import serialize_states

DWARF_VERSION = 4
VALUE_PRESENT = object()

class Address(int):
    pass

# distinct from the elftools LocationEntry - no entry_offset and the loc is a parsed expr
LocationEntry = namedtuple("LocationEntry", ("begin_offset", "end_offset", "location"))


def serialize(units, arch: archinfo.Arch):
    s = _Serializer(arch)

    for unit in units:
        s.write_unit(unit)

    for name, data in list(s.result.items()):
        if not data:
            s.result.pop(name)

    return s.result

class _Serializer:
    def __init__(self, arch):
        self.result = {
            '.debug_info': bytearray(),
            '.debug_abbrev': bytearray(),
            '.debug_str': bytearray(1),
            '.debug_loc': bytearray(),
            '.debug_line': bytearray(),
            '.debug_ranges': bytearray(),
        }
        self.arch = arch
        self.expr_serializer = DWARFExprSerializer(arch)

        self.abbrev_cache = {}
        self.abbrev_ctr = 1

        self.string_cache = {b'': 0}
        self.string_ctr = 1

        self.reference_cache = {} # id -> offset
        self.info_offset = 0
        self.pending_references = {} # id -> (object, [offset to insert reference])

        self.current_unit = None

    @property
    def current_offset(self):
        return len(self.result['.debug_info']) - self.info_offset

    def write_unit(self, unit):
        self.current_unit = unit
        self.info_offset = len(self.result['.debug_info'])
        abbrev_offset = len(self.result['.debug_abbrev'])
        endness = '<' if self.arch.memory_endness == archinfo.Endness.LE else '>'

        # allocate header
        self.result['.debug_info'].extend(bytes(0xb))

        self.abbrev_cache = {}
        self.abbrev_ctr = 1
        self.reference_cache = {}
        self.pending_references = {}
        self.write_die(unit, True)
        self.result['.debug_abbrev'].append(0)

        if len(self.pending_references) != 0:
            raise Exception("Reference to object(s) which were not included in the DIE tree: \n" + '\n'.join(pprint.pformat(obj[0]) for obj in self.pending_references.values()))

        # fill header
        info_end = len(self.result['.debug_info'])
        info_size = info_end - self.info_offset - 4
        struct.pack_into(endness + 'IHIB', self.result['.debug_info'], self.info_offset, info_size, DWARF_VERSION, abbrev_offset, self.arch.bytes)

    def write_die(self, unit, is_last_sibling):
        # a unit is a dict with entries for attributes, an entry for children, and an entry for the tag
        self.reference_cache[id(unit)] = self.current_offset
        if id(unit) in self.pending_references:
            targets = self.pending_references.pop(id(unit))[1]
            for target in targets:
                struct.pack_into(self.arch.struct_fmt(4), self.result['.debug_info'], target, self.current_offset)

        tag = unit['tag']
        children = unit.get('children', [])
        attrs = sorted(x for x in unit if type(x) is int and unit[x] is not None)
        attr_forms = {x: self.get_attribute_form(unit[x]) for x in attrs}
        attr_set = frozenset(attr_forms.items())
        assert len(attr_set) == len(attrs)

        code, new = self.lookup_form(tag, bool(children), bool(children) and not is_last_sibling, attr_set)

        self.result['.debug_info'].extend(self.encode_leb128(code))

        if new:
            self.result['.debug_abbrev'].extend(self.encode_leb128(code))
            self.result['.debug_abbrev'].extend(self.encode_leb128(tag))
            self.result['.debug_abbrev'].append(int(bool(children)))

        for x in attrs:
            self.write_attribute(x, unit[x], attr_forms[x], new)

        ref_offset = len(self.result['.debug_info'])
        if children and not is_last_sibling:
            self.write_attribute(enums.ENUM_DW_AT['DW_AT_sibling'], None, enums.ENUM_DW_FORM['DW_FORM_ref4'], new)

        # null attribute terminator
        if new:
            self.result['.debug_abbrev'].extend(bytes(2))

        for i, child in enumerate(children):
            self.write_die(child, i == len(children) - 1)
        if children:
            self.result['.debug_info'].append(0)

        if children and not is_last_sibling:
            struct.pack_into(self.arch.struct_fmt(4), self.result['.debug_info'], ref_offset, self.current_offset)

    def lookup_form(self, tag, has_children, has_sibling_attr, attrs: frozenset):
        # if this function returns True as the second parameter, you must write the abbreviation immediately
        key = (tag, has_children, has_sibling_attr, attrs)
        new = False

        code = self.abbrev_cache.get(key, None)
        if code is None:
            code = self.abbrev_ctr
            self.abbrev_ctr += 1
            self.abbrev_cache[key] = code
            new = True

        return code, new

    def lookup_string(self, string):
        assert b'\0' not in string

        offset = self.string_cache.get(string, None)
        if offset is None:
            offset = self.string_ctr
            self.string_cache[string] = offset
            self.result['.debug_str'].extend(string)
            self.result['.debug_str'].append(0)
            self.string_ctr += len(string) + 1

        return offset


    def get_attribute_form(self, attr):
        if type(attr) is Address:
            return enums.ENUM_DW_FORM['DW_FORM_addr']
        if type(attr) is list and attr and type(attr[0]) is LocationEntry:
            return enums.ENUM_DW_FORM['DW_FORM_sec_offset']
        if type(attr) is list and attr and type(attr[0]) is lineprogram.LineState:
            return enums.ENUM_DW_FORM['DW_FORM_sec_offset']
        if type(attr) is list and attr and type(attr[0]) in (RangeEntry, BaseAddressEntry):
            return enums.ENUM_DW_FORM['DW_FORM_sec_offset']
        if type(attr) is int:
            if -0x80 <= attr <= 0x7f:
                return enums.ENUM_DW_FORM['DW_FORM_data1']
            if -0x8000 <= attr <= 0x7fff:
                return enums.ENUM_DW_FORM['DW_FORM_data2']
            if -0x80000000 <= attr <= 0x7fffffff:
                return enums.ENUM_DW_FORM['DW_FORM_data4']
            return enums.ENUM_DW_FORM['DW_FORM_sdata']
        if type(attr) is bool:
            return enums.ENUM_DW_FORM['DW_FORM_flag']
        if type(attr) in (str, bytes, bytearray):
            return enums.ENUM_DW_FORM['DW_FORM_strp']
        if type(attr) is list and len(attr) > 0 and type(attr[0]) is dwarf_expr.DWARFExprOp:
            return enums.ENUM_DW_FORM['DW_FORM_exprloc']
        if type(attr) is dict and 'tag' in attr:
            return enums.ENUM_DW_FORM['DW_FORM_ref4']
        if attr is VALUE_PRESENT:
            return enums.ENUM_DW_FORM['DW_FORM_flag_present']
        # None is explicitly removed from the attribute dict above here
        raise TypeError("Can't handle attribute %s" % attr)

    def write_attribute(self, name, attr, form, building_abbrev):
        if building_abbrev:
            self.result['.debug_abbrev'].extend(self.encode_leb128(name))
            self.result['.debug_abbrev'].extend(self.encode_leb128(form))

        if form == enums.ENUM_DW_FORM['DW_FORM_addr']:
            self.result['.debug_info'].extend(struct.pack(self.arch.struct_fmt(), int(attr)))
        if form == enums.ENUM_DW_FORM['DW_FORM_data1']:
            self.result['.debug_info'].extend(struct.pack(self.arch.struct_fmt(1, True), attr))
        if form == enums.ENUM_DW_FORM['DW_FORM_data2']:
            self.result['.debug_info'].extend(struct.pack(self.arch.struct_fmt(2, True), attr))
        if form == enums.ENUM_DW_FORM['DW_FORM_data4']:
            self.result['.debug_info'].extend(struct.pack(self.arch.struct_fmt(4, True), attr))
        if form == enums.ENUM_DW_FORM['DW_FORM_sdata']:
            self.result['.debug_info'].extend(self.encode_leb128(attr))
        if form == enums.ENUM_DW_FORM['DW_FORM_flag']:
            self.result['.debug_info'].extend(bytes([int(attr)]))
        if form == enums.ENUM_DW_FORM['DW_FORM_strp']:
            if type(attr) is str:
                attr = attr.encode('utf-8')
            self.result['.debug_info'].extend(struct.pack(self.arch.struct_fmt(4), self.lookup_string(attr)))
        if form == enums.ENUM_DW_FORM['DW_FORM_ref4']:
            if attr is None:
                self.result['.debug_info'].extend(bytes(4))
            elif id(attr) in self.reference_cache:
                self.result['.debug_info'].extend(struct.pack(self.arch.struct_fmt(4), self.reference_cache[id(attr)]))
            elif id(attr) in self.pending_references:
                self.pending_references[id(attr)][1].append(len(self.result['.debug_info']))
                self.result['.debug_info'].extend(bytes(4))
            else:
                self.pending_references[id(attr)] = (attr, [len(self.result['.debug_info'])])
                self.result['.debug_info'].extend(bytes(4))
        if form == enums.ENUM_DW_FORM['DW_FORM_exprloc']:
            seq = self.expr_serializer.serialize_expr(attr)
            self.result['.debug_info'].extend(self.encode_leb128(len(seq)))
            self.result['.debug_info'].extend(seq)
        if form == enums.ENUM_DW_FORM['DW_FORM_flag_present']:
            pass
        if form == enums.ENUM_DW_FORM['DW_FORM_sec_offset']:
            if type(attr) is list and type(attr[0]) is LocationEntry:
                section = '.debug_loc'
                data = bytearray()
                offset = 0
                for item in attr:
                    low_pc = self.current_unit.get(enums.ENUM_DW_AT['DW_AT_low_pc'], 0)
                    data.extend(struct.pack(self.arch.struct_fmt(), item.begin_offset - low_pc))
                    data.extend(struct.pack(self.arch.struct_fmt(), item.end_offset - low_pc))  # TODO is this right?
                    seq = self.expr_serializer.serialize_expr(item.location)
                    data.extend(struct.pack(self.arch.struct_fmt(2), len(seq)))
                    data.extend(seq)
                data.extend(struct.pack(self.arch.struct_fmt(), 0))
                data.extend(struct.pack(self.arch.struct_fmt(), 0))
            elif type(attr) is list and type(attr[0]) is lineprogram.LineState:
                section = '.debug_line'
                offset = 0
                data = serialize_states(self.arch, attr)
            elif type(attr) is list and type(attr[0]) in (BaseAddressEntry, RangeEntry):
                section = '.debug_ranges'
                offset = 0
                data = bytearray()
                for item in attr:
                    if type(item) is RangeEntry:
                        # ummmm TODO base addresses
                        data.extend(struct.pack(self.arch.struct_fmt(), item.begin_offset))
                        data.extend(struct.pack(self.arch.struct_fmt(), item.end_offset))
                    elif type(item) is BaseAddressEntry:
                        data.extend(struct.pack(self.arch.struct_fmt(signed=True), -1))
                        data.extend(struct.pack(self.arch.struct_fmt(), item.base_address))
                data.extend(struct.pack(self.arch.struct_fmt(), 0))
                data.extend(struct.pack(self.arch.struct_fmt(), 0))
            else:
                raise TypeError("Not sure what kind of section reference this is")

            self.result['.debug_info'].extend(struct.pack(self.arch.struct_fmt(4), len(self.result[section]) + offset))
            self.result[section].extend(data)

    @staticmethod
    def encode_leb128(num):
        # roughly from wikipedia
        more = True
        result = bytearray()
        while more:
            byte = num & 0x7f
            num >>= 7

            if (num == 0 and (byte & 0x40) == 0) or (num == -1 and (byte & 0x40) == 0x40):
                more = False
            else:
                byte |= 0x80

            result.append(byte)

        return result
