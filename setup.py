
try:
    from setuptools import setup
    from setuptools import find_packages
    packages = find_packages()
except ImportError:
    from distutils.core import setup
    import os
    packages = [x.strip('./').replace('/','.') for x in os.popen('find -name "__init__.py" | xargs -n1 dirname').read().strip().split('\n')]

setup(
    name='dwarfwrite',
    version='0.1',
    python_requires='>=3.6',
    packages=packages,
    install_requires=[],
    description='Library for serializing structured data to DWARF format',
    url='https://github.com/rhelmot/dwarfwrite',
)
