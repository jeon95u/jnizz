from lib.core.jnizzparser import JnizzParser
from sys import argv
import os
import shutil


if __name__ == "__main__":
    argv_parser = JnizzParser(argv)
    commander = argv_parser.result[0]
    user_args = argv_parser.result[1]
    pack_dir = os.path.dirname(os.path.abspath(__file__))

    ##############################
    # "init" command executed
    if commander == 0:
        os.mkdir(user_args['name'])
        os.chdir(user_args['name'])
        copy_libs = ['analyzer', 'fuzzer', 'dashboard']
        for lib in copy_libs:
            orig_path = os.path.join(pack_dir, 'lib', lib)
            shutil.copytree(orig_path, os.path.join(os.getcwd(), lib))
        user_files = ['run.py', 'settings.py']
        for uf in user_files:
            orig_path = os.path.join(pack_dir, 'lib', 'template', uf)
            shutil.copy(orig_path, os.path.join(os.getcwd(), uf))

    # "init" command ended
    ##############################

    ##############################
    # "add-apk" command executed
    elif commander == 1:
        orig_path = os.path.join(pack_dir, 'lib', 'template', 'add-apk.py')
        with open(orig_path, 'r') as f:
            new_file = f.read()
            f.close()
            new_file = new_file.replace('{{user_apk_class}}', user_args['name'] + 'Class')\
                .replace('{{user_apk_name}}', user_args['name'])
            new_path = os.path.join(os.getcwd(), user_args['name'] + '.py')
            with open(new_path, 'w') as f2:
                f2.write(new_file)
                f2.close()
    # "add-apk" command ended
    ##############################


    ##############################
    # "show" command executed
    else:
        pass
    # "show" command ended
    ##############################
