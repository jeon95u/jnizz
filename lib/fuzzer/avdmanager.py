import subprocess
from settings import SDK_CONFIG
from analyzer.analyzer import APK
from fuzzer.exploitable import Tombstone, Exploitable
import hashlib
import random
import os
import signal
import sys
import errno
from time import sleep, time
import sqlite3


class AvdManager:
    path = SDK_CONFIG["avdmanager"]

    # TODO: avd마다 이미지 분리
    android_ver = SDK_CONFIG["avd"]["android_ver"]
    abi = SDK_CONFIG["avd"]["abi"]

    def __init__(self, apk: APK, func_map, load_exist=True):
        self._target_apk = apk
        self._func_map = func_map
        self._avds = {}
        if load_exist:
            self.init_with_existing_avd()

    def init_with_existing_avd(self):
        cmd = [
            Avd.emul_path,
            '-list-avds'
        ]
        with subprocess.Popen(cmd, stdout=subprocess.PIPE) as proc:
            avd_list = proc.stdout.read().decode()
            avd_list = avd_list.split('\n')
            for a_name in avd_list:
                if self._target_apk.name + '_' in a_name:
                    state_str = "%s for %s found. it loaded." % (a_name, self._target_apk.name)
                    print(state_str)
                    self._avds[a_name] = Avd(a_name, self._target_apk, self._func_map)

    def create(self):
        new_avd_name = '%s_%s' % (self._target_apk.name,
                                  hashlib.sha256(str(random.random()).encode()).hexdigest())
        print("Creating %s..." % new_avd_name)
        cmd = [
            'echo', 'no', '|',
            AvdManager.path,
            'create', 'avd',
            '--force',
            '-n', new_avd_name,
            '-k', '"system-images;android-%d;%s"' % (AvdManager.android_ver, AvdManager.abi)
        ]
        subprocess.run(' '.join(cmd), shell=True, stdout=subprocess.PIPE)
        if self._avd_exist(new_avd_name):
            self._avds[new_avd_name] = Avd(new_avd_name, self._target_apk, self._func_map)
            state_str = 'New avd %s for %s created.\n' % (new_avd_name, self._target_apk.name)
            print(state_str)
            return self._avds[new_avd_name]
        else:
            return None

    def _avd_exist(self, avd_name):
        cmd = [
            Avd.emul_path,
            '-list-avds'
        ]
        with subprocess.Popen(cmd, stdout=subprocess.PIPE) as proc:
            avd_list = proc.stdout.read().decode()
            avd_list = avd_list.split('\n')
            if avd_name in avd_list:
                return True
            else:
                return False

    def delete_all(self):
        k = list(self._avds.keys())
        for i in range(0, len(k)):
            self.delete(k[i])

    def delete(self, avd_name):
        if avd_name not in self._avds:
            return None

        if self._avds[avd_name].state == Avd.RUNNING:
            self._avds[avd_name].stop()

        cmd = [
            AvdManager.path,
            'delete', 'avd',
            '-n', avd_name
        ]
        subprocess.run(cmd, stdout=subprocess.PIPE)
        if not self._avd_exist(avd_name):
            print(avd_name + " deleted.")
            del self._avds[avd_name]
            return True
        else:
            return False

    def fuzz(self):
        if len(self._avds) == 0:
            raise Exception("No avd found.")

        ports = []

        for avd_name, avd_obj in self._avds.items():
            avd_obj.run()
            ports.append(avd_obj.emul_port)

        print('\nFuzzing on port %s...' % ", ".join(str(x) for x in ports))

    def check(self):
        for avd_name, avd_obj in self._avds.items():
            if avd_obj.state == Avd.RUNNING:
                avd_obj.check_tombstone()

    def pause(self):
        for avd_name in self._avds:
            self._avds[avd_name].stop()

    def save_tombstones(self):
        tomb_dir = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), 'tombstones')
        if not os.path.exists(tomb_dir):
            try:
                os.makedirs(tomb_dir)
            except OSError as exc:
                if exc.errno != errno.EEXIST:
                    raise

        cnt = 0
        for avd in self._avds.values():
            for tombstone in avd.tombstones:
                if tombstone.exploitable_lv == Exploitable.LV_NOT_CHECKTED:
                    continue
                with open(os.path.join(tomb_dir, 'tombstone_' + str(time())), "w") as f:
                    pkg_info = 'PKG name: ' + tombstone.pkg_name
                    func_info = 'JNI call: ' + tombstone.crashed_func_name
                    args_info = 'Arguments: ' + ', '.join(map(str, tombstone.args))
                    exploitable_info = 'Exploitable Level: ' + Exploitable.EXPLOITABLE_TXT[tombstone.exploitable_lv]
                    f.write('\n'.join([pkg_info, func_info, args_info, exploitable_info, tombstone.text]))
                    f.close()
                    cnt += 1
        print(str(cnt) + " tombstone file(s) saved at the directory \"tombstones\".")


class Avd:
    PAUSED = 0
    RUNNING = 1
    emul_path = SDK_CONFIG["emulator"]
    adb_path = SDK_CONFIG["adb"]
    tombstone_cnt = 0
    emul_auto_inc_id = 6000

    def __init__(self, name, apk: APK, func_map):
        self._name = name
        self._target_apk = apk
        self._func_map = func_map[2]
        self._state = Avd.PAUSED
        self._process = None
        self.emul_port = -1
        self._tombstone_idx = 0
        self._package_name = func_map[0]
        self._class_name = func_map[1]
        self.tombstones = []

    def run(self):
        if self._state == Avd.PAUSED:
            self.emul_port = Avd.emul_auto_inc_id
            Avd.emul_auto_inc_id += 2
            cmd = [
                Avd.emul_path,
                '-avd', self._name,
                '-port', str(self.emul_port),
                '-no-audio', '-no-window'
            ]

            state_str = '\n%s is running on port %d' % (self._name, self.emul_port)
            print(state_str)
            self._process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            self._init_fuzzer()
            sleep(5)
            self._process.terminate()
            print("Wait for reboot.....")
            sleep(3)
            self._process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
            self._state = Avd.RUNNING
            self._init_fuzzer()

    def _init_fuzzer(self):
        adb_test_cmd = [
            Avd.adb_path,
            '-s', 'emulator-' + str(self.emul_port),
            'shell',
            'ls'
        ]

        while True:
            sh = subprocess.Popen(adb_test_cmd, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
            msg = sh.stderr.read().decode()
            if 'error:' not in msg:
                break

        pack_dir = os.path.dirname(os.path.abspath(__file__))
        radamsa_push_cmd = [
            Avd.adb_path,
            '-s', 'emulator-' + str(self.emul_port),
            'push',
            os.path.join(pack_dir, 'radamsa_x86_s'),
            '/data/local/tmp/'
        ]

        while True:
            sh2 = subprocess.Popen(radamsa_push_cmd, stdout=subprocess.PIPE)
            msg = sh2.stdout.read().decode()
            print(msg)
            if 'error:' in msg:
                print("retry pushing radamsa...")
                sleep(3)
            else:
                break
        print("radamsa pushed into emulator-%s." % (str(self.emul_port)))


        radamsa_chmod_cmd = [
            Avd.adb_path,
            '-s', 'emulator-' + str(self.emul_port),
            'shell',
            '"su 0 chmod 777 /data/local/tmp/radamsa_x86_s"'
        ]
        os.system(" ".join(str(x) for x in radamsa_chmod_cmd))
        print("radamsa mod changed.")

        apk_install_cmd = [
            Avd.adb_path,
            '-s', 'emulator-' + str(self.emul_port),
            'install',
            '-r', self._target_apk.path
        ]
        while True:
            sh3 = subprocess.Popen(apk_install_cmd, stdout=subprocess.PIPE)
            msg = sh3.stdout.read().decode()
            print(msg)
            if 'Error:' in msg or 'Aborted' in msg:
                print("retry installing targeted apk...")
                sleep(3)
            else:
                break
        print("targeted apk installed on emulator-%s." % (str(self.emul_port)))

        fuzzing_script = '''\
tombstone_idx=0

while true; do
{{parameter_script}}
done
'''
        PARAM_SCRIPT = '''\
    j=$(printf %%02s $tombstone_idx)
    echo $j
    INPUT_FILE=/data/local/tmp/tombstone_input_${j}_{{func_name}}
    {{radamsa_script}}
    {{am_script}}
    am force-stop %s
    if [ -e /data/tombstones/tombstone_$j ]; then
        tombstone_idx=$(((tombstone_idx + 1)%%10))
    fi
''' % self._package_name
        for i in self._func_map:
            if self._func_map[i] is None:
                continue
            types = self._func_map[i]
            cnt = len(types)
            param = PARAM_SCRIPT

            param = param.replace('{{func_name}}', i)

            run_sh = 'am start -a android.intent.action.MAIN -n %s/.%s' % (self._package_name, self._class_name)
            for j in range(0, cnt):
                if "Integer" in types[j]:
                    param = param.replace('{{radamsa_script}}', 'echo 1 | /data/local/tmp/radamsa_x86_s -m num > ${INPUT_FILE}_%d\n    {{radamsa_script}}' % j)
                elif "String" in types[j]:
                    param = param.replace('{{radamsa_script}}', 'echo "A" | /data/local/tmp/radamsa_x86_s -m ab > ${INPUT_FILE}_%d\n    {{radamsa_script}}' % j)
                run_sh += ' -e %s_%d "`cat ${INPUT_FILE}_%d`"' % (i, j, j)

            param = param.replace('\n    {{radamsa_script}}', '')
            param = param.replace('{{am_script}}', run_sh)
            fuzzing_script = fuzzing_script.replace('{{parameter_script}}', param + '\n{{parameter_script}}')

        fuzzing_script = fuzzing_script.replace('\n{{parameter_script}}', '')
        script_path = os.path.join(os.path.split(os.path.abspath(self._target_apk.path))[0], 'fuzzing.sh')
        with open(script_path, 'w') as f:
            f.write(fuzzing_script)

        sh_inject_cmd = [
            Avd.adb_path,
            '-s', 'emulator-' + str(self.emul_port),
            'push',
            script_path,
            '/data/local/tmp/fuzzing.sh'
        ]

        while True:
            sh4 = subprocess.Popen(sh_inject_cmd, stdout=subprocess.PIPE)
            msg = sh4.stdout.read().decode()
            print(msg)
            if 'error:' in msg:
                print("retry pushing script...")
                sleep(3)
            else:
                break
        print("script pushed into emulator-%s." % (str(self.emul_port)))

        script_chmod_cmd = [
            Avd.adb_path,
            '-s', 'emulator-' + str(self.emul_port),
            'shell',
            '"su 0 chmod 777 /data/local/tmp/fuzzing.sh"'
        ]
        os.system(" ".join(str(x) for x in script_chmod_cmd))
        print("script mod changed.")

        script_exec_cmd = [
            Avd.adb_path,
            '-s', 'emulator-' + str(self.emul_port),
            'shell',
            '"/data/local/tmp/fuzzing.sh"'
        ]
        subprocess.Popen(script_exec_cmd, stdout=subprocess.PIPE)

    def stop(self):
        if self._state == Avd.RUNNING:
            # TODO: 이미지 삭제 안
            self._process.terminate()
            self._state = Avd.PAUSED

    def check_tombstone(self):
        if self._state == Avd.RUNNING:
            conn = sqlite3.connect(SDK_CONFIG['database'])
            cs = conn.cursor()
            while True:
                target = '/data/tombstones/tombstone_%02d' % (self._tombstone_idx)
                ls_tombstone_cmd = [
                    Avd.adb_path,
                    '-s', 'emulator-' + str(self.emul_port),
                    'shell',
                    'ls %s' % (target)
                ]
                sh = subprocess.Popen(ls_tombstone_cmd, stdout=subprocess.PIPE)
                msg = sh.stdout.read().decode()
                if 'No such file or directory' in msg:
                    break

                input_path = '/data/local/tmp/tombstone_input_%02d*' % (self._tombstone_idx)
                ls_input_cmd = [
                    Avd.adb_path,
                    '-s', 'emulator-' + str(self.emul_port),
                    'shell',
                    'ls %s' % (input_path)
                ]
                sh2 = subprocess.Popen(ls_input_cmd, stdout=subprocess.PIPE)
                input_file_list = sh2.stdout.read().decode().split('\r\n')
                input_args = []
                func_name = input_file_list[0].split('_')[-2]
                for i in input_file_list[:-1]:
                    cat_input_cmd = [
                        Avd.adb_path,
                        '-s', 'emulator-' + str(self.emul_port),
                        'shell',
                        'cat %s' % (i)
                    ]
                    sh3 = subprocess.Popen(cat_input_cmd, stdout=subprocess.PIPE)
                    input_txt = sh3.stdout.read().decode()
                    input_args.append(input_txt)

                cat_rm_tombstone_cmd = [
                    Avd.adb_path,
                    '-s', 'emulator-' + str(self.emul_port),
                    'shell',
                    'cat %s && rm %s' % (target, target)
                ]
                sh4 = subprocess.Popen(cat_rm_tombstone_cmd, stdout=subprocess.PIPE)
                tomb_txt = sh4.stdout.read().decode()
                
                tomb = Tombstone(pkg_name=self._package_name, text=tomb_txt, crashed_func_name=func_name, args=input_args)
                self.tombstones.append(tomb)

                if self.tombstones[-1].exploitable_lv != Exploitable.LV_NOT_CHECKTED:
                    cs.execute("INSERT INTO crash(pkg_name, tomb_txt, crashed_func_name, args, exploitable, time) values (?, ?, ?, ?, ?, ?);", (tomb.pkg_name, tomb.text, tomb.crashed_func_name, ', '.join(map(str, tomb.args)), Exploitable.EXPLOITABLE_TXT[tomb.exploitable_lv], time()))
                    conn.commit()
                    print("A tombstone generated.")

                self._inc_tombstone_idx()

    def _inc_tombstone_idx(self):
        self._tombstone_idx = (self._tombstone_idx + 1) % 10

    @property
    def name(self):
        return self._name

    @property
    def state(self):
        return self._state
