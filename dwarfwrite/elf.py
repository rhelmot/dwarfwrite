import os
import shutil
import subprocess
import tempfile

from elftools.elf.elffile import ELFFile

def dump_elf(result, arch, outfile, infile=None):
    result_update = {}
    if infile is not None:
        with open(infile, 'rb') as fp:
            elf = ELFFile(fp)
            for section in elf.iter_sections():
                if section.name in result:
                    result_update[section.name] = result.pop(section.name)

    tmp = tempfile.mkdtemp()
    with open(os.path.join(tmp, 'zero'), 'wb') as fp:
        fp.write(b'\0')

    for f in result:
        with open(os.path.join(tmp, f), 'wb') as fp:
            fp.write(result[f])
    for f in result_update:
        with open(os.path.join(tmp, f), 'wb') as fp:
            fp.write(result_update[f])

    # TODO add bfd_name to archinfo
    linux_name = arch.linux_name.replace('_', '-')
    if arch.name.startswith("ARM"):
        linux_name = ('big' if arch.memory_endness == 'Iend_BE' else 'little') + linux_name
    abi = 'elf%s-%s' % (arch.bits, linux_name)
    extra_args = []
    for f in result:
        extra_args.append('--add-section')
        extra_args.append('%s=%s' % (f, os.path.join(tmp, f)))
    for f in result_update:
        extra_args.append('--update-section')
        extra_args.append('%s=%s' % (f, os.path.join(tmp, f)))
    if infile is None:
        in_flags = ['--input-target=binary', '-S', '--remove-section=.data']
        in_args = [os.path.join(tmp, 'zero')]
    else:
        in_flags = []
        in_args = [infile]
    subprocess.check_call(['objcopy', '--output-target=' + abi] + in_flags + extra_args + in_args + [outfile])

    shutil.rmtree(tmp)
