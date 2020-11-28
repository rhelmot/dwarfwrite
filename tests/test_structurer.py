from dwarfwrite.structure import DWARFStructurer

class TestStructurer(DWARFStructurer):
    def root_get_units(self):
        return [1, 2]

    def unit_get_filename(self, unit):
        return str(unit)

    def unit_get_functions(self, unit):
        return [unit, unit * 3]

    def function_get_name(self, func):
        return str(func)

    def function_get_parameters(self, func):
        return [func, func * 3]

    def parameter_get_name(self, param):
        return str(param)

def test_structurer():
    result = TestStructurer().run()
    import pprint; pprint.pprint(result)

if __name__ == '__main__':
    test_structurer()