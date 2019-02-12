import zipfile
import tempfile
import os
import shutil
import re
import struct
import time
import json
import operator
from settings import SDK_CONFIG ###


strings = lambda data: re.findall(b'[^\x00-\x1F\x7F-\xFF]{4,}', data)
endian = lambda data: struct.unpack('<L', data)[0] if len(data) == 4 else struct.unpack('<H', data)[0]
path_join = lambda path: ''.join(os.path.join(str(x), '') for x in path)[:-1]


class Analyzer:
    def __init__(self):
        self.tmp_dir = tempfile.mkdtemp()

    def analyze(self, apk):
        so_table = []
        JNI_function_table = []
        JNI_function_ori_table = {}
        ret_so_name = ''
        so_dir = path_join([self.tmp_dir, 'app', 'src', 'main', 'jniLibs', 'x86'])

        with open(path_join([self.tmp_dir, 'ori.apk']), 'wb') as f:
            f.write(apk)

        apk_zip = zipfile.ZipFile(path_join([self.tmp_dir, 'ori.apk']))

        dex_binary_list = []
        for file_name in apk_zip.namelist():
            ext = file_name.split('.')[-1]
            if ext == 'dex':
                dex_binary_list.append(apk_zip.read(file_name))
            elif ext == 'so':
                ### Change ELF Parsing ###
                so_name = file_name.split('/')[-1].split('.')[0]

                if 'x86' in file_name and '64' not in file_name:
                    apk_zip.extract(file_name, so_dir)
                    shutil.copy(os.path.join(so_dir, file_name), os.path.join(so_dir, so_name + '.so'))
                    shutil.rmtree(os.path.join(so_dir, 'lib'))
                    ret_so_name = so_name + '.so'

                if so_name in so_table:
                    continue

                for tmp_string in strings(apk_zip.read(file_name)):
                    if b'Java_' in tmp_string:
                        tmp = tmp_string.split(b'Java_')[1].replace(b'_', b'.').replace(b'.1', b'_').decode()
                        JNI_function_table.append(tmp)
                        JNI_function_ori_table[tmp] = tmp_string.decode()

                so_table.append(so_name)
        apk_zip.close()

        return_table = []
        for dex_binary in dex_binary_list:
            # ''' ''' dex parsing ''' '''
            if dex_binary[:3] != b'dex':
                exit('[-] Error: not dex file')

            # ''' dex header parsing '''
            dex_header = {}
            dex_header['magic'] = dex_binary[0x00:0x08]
            dex_header['checksum'] = endian(dex_binary[0x08:0x0c])
            dex_header['sha1'] = dex_binary[0x0c:0x20]
            dex_header['file_size'] = endian(dex_binary[0x20:0x24])
            dex_header['header_size'] = endian(dex_binary[0x24:0x28])
            dex_header['endian_constant'] = endian(dex_binary[0x28:0x2c])
            dex_header['link_size'] = endian(dex_binary[0x2c:0x30])
            dex_header['link_offset'] = endian(dex_binary[0x30:0x34])
            dex_header['map_offset'] = endian(dex_binary[0x34:0x38])
            dex_header['string_id_size'] = endian(dex_binary[0x38:0x3c])
            dex_header['string_id_offset'] = endian(dex_binary[0x3c:0x40])
            dex_header['type_id_size'] = endian(dex_binary[0x40:0x44])
            dex_header['type_id_offset'] = endian(dex_binary[0x44:0x48])
            dex_header['proto_id_size'] = endian(dex_binary[0x48:0x4c])
            dex_header['proto_id_offset'] = endian(dex_binary[0x4c:0x50])
            dex_header['field_id_size'] = endian(dex_binary[0x50:0x54])
            dex_header['field_id_offset'] = endian(dex_binary[0x54:0x58])
            dex_header['method_id_size'] = endian(dex_binary[0x58:0x5c])
            dex_header['method_id_offset'] = endian(dex_binary[0x5c:0x60])
            dex_header['class_def_size'] = endian(dex_binary[0x60:0x64])
            dex_header['class_def_offset'] = endian(dex_binary[0x64:0x68])
            dex_header['data_size'] = endian(dex_binary[0x68:0x6c])
            dex_header['data_offset'] = endian(dex_binary[0x6c:0x70])

            if dex_header['file_size'] != len(dex_binary):
                exit('[-] Error: binary size != header size')

            # ''' make string table using by id '''
            string_table = []
            for i in range(dex_header['string_id_size']):
                offset = endian(
                    dex_binary[dex_header['string_id_offset'] + i * 4:dex_header['string_id_offset'] + i * 4 + 4])
                string_size = dex_binary[offset]
                string = dex_binary[offset + 1:offset + 1 + string_size]
                string_table.append(string)

            ''' make type id table '''
            type_id_table = []
            for i in range(dex_header['type_id_size']):
                type_id_table.append(
                    endian(dex_binary[dex_header['type_id_offset'] + i * 4:dex_header['type_id_offset'] + i * 4 + 4]))

            # ''' make prototype list '''
            proto_table = []
            for i in range(dex_header['proto_id_size']):
                shorty_idx = endian(
                    dex_binary[dex_header['proto_id_offset'] + i * 12 + 0:dex_header['proto_id_offset'] + i * 12 + 4])
                return_type_idx = endian(
                    dex_binary[dex_header['proto_id_offset'] + i * 12 + 4:dex_header['proto_id_offset'] + i * 12 + 8])
                param_offset = endian(
                    dex_binary[dex_header['proto_id_offset'] + i * 12 + 8:dex_header['proto_id_offset'] + i * 12 + 12])
                proto_table.append((shorty_idx, return_type_idx, param_offset))

            # ''' make method table '''
            method_list = []
            for i in range(dex_header['method_id_size']):
                class_idx = endian(
                    dex_binary[dex_header['method_id_offset'] + i * 8 + 0:dex_header['method_id_offset'] + i * 8 + 2])
                proto_idx = endian(
                    dex_binary[dex_header['method_id_offset'] + i * 8 + 2:dex_header['method_id_offset'] + i * 8 + 4])
                name_idx = endian(
                    dex_binary[dex_header['method_id_offset'] + i * 8 + 4:dex_header['method_id_offset'] + i * 8 + 8])
                method_list.append((class_idx, proto_idx, name_idx))

            for method in method_list:
                class_name = string_table[type_id_table[method[0]]].decode()
                method_name = string_table[method[2]].decode()

                if class_name[0] == 'L':
                    class_name = class_name[1:]

                check_string = (class_name.replace(';', '') + '.' + method_name).replace('/', '.')

                if check_string in JNI_function_table:
                    if proto_table[method[1]][2] != 0:
                        param_offset = proto_table[method[1]][2]
                        param_cnt = endian(dex_binary[param_offset:param_offset + 4])
                        param_type_table = []
                        for i in range(2, param_cnt + 2):
                            param_type = endian(dex_binary[param_offset + i * 2:param_offset + i * 2 + 2])
                            param_type_table.append(string_table[type_id_table[param_type]].decode())
                    else:
                        param_cnt = 0
                        param_type_table = []

                    return_table.append([check_string, [param_cnt, param_type_table]])

        return Report(JNI_function_ori_table, ret_so_name, return_table)

    def make_custom_app(self, name, report):
        pack_dir = os.path.dirname(os.path.abspath(__file__))
        base_zip_path = os.path.join(pack_dir, 'base.zip')
        base_zip = zipfile.ZipFile(base_zip_path)
        base_zip.extractall(self.tmp_dir)

        # user SDK path setting
        with open(path_join([self.tmp_dir, 'local.properties']), 'wb') as f:
            sdk_dir = SDK_CONFIG['sdk']
            f.write(b'sdk.dir=%s' % sdk_dir.encode())

        so_dir = path_join([self.tmp_dir, 'app', 'src', 'main', 'jniLibs', 'x86'])

        jni_ori_table = report.JNI_func_list
        so_name = report.so_name
        parse_result = report.JNI_param_list

        native_ret = ''
        argv_table = []
        mapping_table = {}
        class_list = {}
        pack_list = {}
        for idx, jni_func in enumerate(parse_result):
            real_func_name = jni_func[0].split('.')[-1]
            real_class_name = jni_func[0].split('.')[-2]
            real_package_name = '.'.join(jni_func[0].split('.')[:-2])
            # print(real_package_name, real_class_name, real_func_name)

            try:
                class_list[real_class_name] += 1
                pack_list[real_class_name] = real_package_name
            except:
                class_list[real_class_name] = 1
                pack_list[real_class_name] = real_package_name

        one_class = (max(class_list.items(), key=operator.itemgetter(1))[0])

        for idx, jni_func in enumerate(parse_result):
            real_func_name = jni_func[0].split('.')[-1]
            real_class_name = jni_func[0].split('.')[-2]
            real_package_name = '.'.join(jni_func[0].split('.')[:-2])

            if one_class != real_class_name:
                continue

            nfn = real_func_name
            argv_type_table = []
            for idid, arg in enumerate(jni_func[1][1]):
                tmp_str = '%s_%d' % (nfn, idid)
                if 'Ljava/lang/String;' == arg:
                    argv_type_table.append(['String ', 'extras.getString("%s")' % tmp_str])
                elif 'I' == arg:
                    argv_type_table.append(['Integer ', 'extras.getInt("%s")' % tmp_str])

            tmp_str = '%s_0' % (nfn)
            if jni_func[1][0] != 0:
                arg_text = ''
                arg_text2 = ''
                for i, d in enumerate(argv_type_table):
                    arg_text += d[0] + chr(97 + i) + ', '
                    arg_text2 += d[1] + ', '

                arg_text = arg_text[:-2]
                arg_text2 = arg_text2[:-2]

                native_ret += 'public native String %s(%s);\n' % (nfn, arg_text)

                argv_table.append('''
                    if(extras.containsKey("%s")){
                        %s(%s);
                    }
                    ''' % (tmp_str, nfn, arg_text2))
                mapping_table[nfn] = [arg_text]

        java_dir = path_join([self.tmp_dir, 'app', 'src', 'main', 'java'])
        for dir_name in jni_func[0].split('.')[:-2]:
            os.mkdir(path_join([java_dir, dir_name]), 0o777)
            java_dir = path_join([java_dir, dir_name])


        new_java_path = path_join([java_dir, one_class+'.java'])
        shutil.move(path_join([self.tmp_dir, 'app', 'src', 'main', 'java', 'MainActivity.java']), new_java_path)

        # build.gradle overwrite
        with open(path_join([self.tmp_dir, 'app', 'build.gradle']), 'rb') as f:
            tmp = f.read()
        with open(path_join([self.tmp_dir, 'app', 'build.gradle']), 'wb') as f:
            f.write(tmp.replace('domain.company.app_name'.encode(), pack_list[one_class].encode()))

        # AndroidManifest.xml overwrite
        with open(path_join([self.tmp_dir, 'app', 'src', 'main', 'AndroidManifest.xml']), 'rb') as f:
            tmp = f.read()
        with open(path_join([self.tmp_dir, 'app', 'src', 'main', 'AndroidManifest.xml']), 'wb') as f:
            f.write(tmp.replace('domain.company.app_name'.encode(), pack_list[one_class].encode()).replace('MainActivity'.encode(), one_class.encode()))

        argv_set_and_func_call = '''
            Bundle extras = this.getIntent().getExtras();
            if(extras != null){
                ''' + '\n'.join(argv_table) + '''
            }
        '''
        with open(new_java_path, 'r') as f:
            java_code = f.read()

        java_code = java_code.replace('domain.company.app_name', pack_list[one_class])
        java_code = java_code.replace('MainActivity', one_class)
        java_code = java_code.replace('{{jni_funcion_list}}', native_ret)
        java_code = java_code.replace('{{argv_set_and_func_call}}', argv_set_and_func_call)
        java_code = java_code.replace('{{so_file_name}}', so_name[3:-3])

        with open(new_java_path, 'w') as f:
            f.write(java_code)


        new_apk_name = str(int(time.time())) + '.apk'
        ret_path = os.getcwd()
        os.chdir(self.tmp_dir)
        os.chmod(path_join([self.tmp_dir, 'gradlew']), 0o777)
        os.system(path_join([self.tmp_dir, 'gradlew']) + ' build')
        new_path = path_join([os.path.split(os.path.abspath(self.tmp_dir))[0], new_apk_name])
        shutil.copy(path_join([self.tmp_dir, 'app', 'build', 'outputs', 'apk', 'debug', 'app-debug.apk']),
                    new_path)

        try:
            shutil.rmtree(self.tmp_dir)
        except:
            pass

        os.chdir(ret_path)
        return (APK(name, new_path), [pack_list[one_class], one_class, mapping_table])


class Report:
    def __init__(self, JNI_func_list, so_name, JNI_param_list):
        self.JNI_func_list = JNI_func_list
        self.so_name = so_name
        self.JNI_param_list = JNI_param_list

    def jsonify(self):
        return json.dumps([self.JNI_func_list, self.so_name, self.JNI_param_list])


class APK:
    def __init__(self, name, path):
        self.analyzer = Analyzer()
        self.path = path
        self.name = name
        self.info = None

    def get_binary(self):
        with open(self.path, 'rb') as f:
            return f.read()

    def get_custom_app(self):
        self.info = self.analyzer.analyze(self.get_binary())
        return self.analyzer.make_custom_app(self.name, self.info)

# if __name__ == '__main__':
#     import sys
#     if len(sys.argv) > 1:
#         file_path = sys.argv[1]
#     else:
#         file_path = '/Users/jeon95u/Downloads/vuln_function_pointer.apk'

#     # base_zip_path = '/Users/jeon95u/Desktop/cap4/analyzer_test/base.zip' # API ver 28
#     # base_zip_path = '/Users/jeon95u/Desktop/capstone4/base.zip' # API ver 23
#     base_zip_path = '/Users/jeon95u/Downloads/ver6.zip'

#     fuzz_apk = APK('fuzz_test', file_path).get_custom_app()
#     print(fuzz_apk)
