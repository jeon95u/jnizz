## jnizz

------

#### usage

```
usage: jnizz [help, -h, --help] COMMAND [ARGS]

The most commonly used jnizz commands are:
   init <project-name>        initialize a JNI shower program source code
   add-apk <apk-name>         add targeted apk to fuzz
   show <apk-name>            show tombstones and exploitable possibility

See 'jnizz COMMAND --help' for more information on a specific command.
```



#### example

```
python3 jnizz.py init {project-name}
python3 jnizz.py add-apk {apk_name}

modify self.file_path in {apk_name}.py
python3 run.py
```



