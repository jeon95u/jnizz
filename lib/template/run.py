from fuzzer.avdmanager import AvdManager
from time import sleep
import traceback
import os

try:
    os.system('python3 dashboard/run.py &')
    am = AvdManager(apk=your_fuzzing_apk, func_map=fuzzing_func_map)
    am.create() # add an avd if you need one
    am.fuzz()

    while (True):
        sleep(1)
        am.check()
except (KeyboardInterrupt, Exception) as err:
    traceback.print_exc()
    am.save_tombstones()
    am.pause()
    am.delete_all()
