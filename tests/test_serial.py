import archinfo
from elftools.dwarf import enums, constants

from dwarfwrite.elf import dump_elf
from dwarfwrite.serial import Address, serialize

def test_basic():
    arch = archinfo.ArchX86()
    unit = {
        'tag': enums.ENUM_DW_TAG['DW_TAG_compile_unit'],
        enums.ENUM_DW_AT['DW_AT_producer']: 'angr :)',
        enums.ENUM_DW_AT['DW_AT_name']: 'test.c',
        enums.ENUM_DW_AT['DW_AT_language']: constants.DW_LANG_C,
        'children': [
            {
                'tag': enums.ENUM_DW_TAG['DW_TAG_subprogram'],
                enums.ENUM_DW_AT['DW_AT_name']: 'main',
            },
            {
                'tag': enums.ENUM_DW_TAG['DW_TAG_subprogram'],
                enums.ENUM_DW_AT['DW_AT_name']: 'foo',
            },
        ],
    }

    result = serialize([unit], arch)
    dump_elf(result, arch, '/tmp/debug.elf')

def test_children():
    arch = archinfo.ArchX86()
    units = [{3: '1',
  19: None,
  'children': [{3: '1',
                17: None,
                18: None,
                73: None,
                'children': [{3: '1', 73: None, 'tag': 5},
                             {3: '3', 73: None, 'tag': 5}],
                'tag': 46},
               {3: '3',
                17: None,
                18: None,
                73: None,
                'children': [{3: '3', 73: None, 'tag': 5},
                             {3: '9', 73: None, 'tag': 5}],
                'tag': 46}],
  'tag': 17},
 {3: '2',
  19: None,
  'children': [{3: '2',
                17: None,
                18: None,
                73: None,
                'children': [{3: '2', 73: None, 'tag': 5},
                             {3: '6', 73: None, 'tag': 5}],
                'tag': 46},
               {3: '6',
                17: None,
                18: None,
                73: None,
                'children': [{3: '6', 73: None, 'tag': 5},
                             {3: '18', 73: None, 'tag': 5}],
                'tag': 46}],
  'tag': 17}]

    result = serialize(units, arch)
    dump_elf(result, arch, '/tmp/debug.elf')


if __name__ == '__main__':
    test_children()
