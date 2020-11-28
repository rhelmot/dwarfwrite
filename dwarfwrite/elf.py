import os
import shutil
import subprocess
import tempfile

def dump_elf(result, arch, outfile):
    tmp = tempfile.mkdtemp()
    with open(os.path.join(tmp, 'zero'), 'wb') as fp:
        fp.write(b'\0')

    for f in result:
        with open(os.path.join(tmp, f), 'wb') as fp:
            fp.write(result[f])

    architecture = arch.linux_name
    # TODO add bfd_name to archinfo
    abi = 'elf%s-%s' % (arch.bits, arch.linux_name.replace('_', '-'))
    extra_args = []
    for f in result:
        extra_args.append('--add-section')
        extra_args.append('.%s=%s' % (f, os.path.join(tmp, f)))
    subprocess.check_call(['objcopy', '--input-target=binary', '--output-target=' + abi, '-S', '--remove-section=.data'] + extra_args + [os.path.join(tmp, 'zero'), outfile])

    shutil.rmtree(tmp)
