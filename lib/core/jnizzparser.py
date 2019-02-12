class JnizzParser:
    command_idx = 0
    def __init__(self, argv_list):
        self.argv = argv_list
        self.result = []
        self.commands = ["init", "show"]
        self.command_help = [
                "init <project-name>\n",
                "add-apk <apk-name>",
                "show <apk-name>\n"
        ]
        self.command_options_help = [
            [
                # """    -a, --address <ip address>  set server ip address to show data
                #                 (default: localhost)\n""",
                # """    -p, --port <port number>    set port
                #                 (default: 9200)\n"""
            ],
            [
                # """    -t, --time <timeout>                set timeout
                #                         (default: infinity)\n""",
                # """    -s, --script <shell script>         execute user-defined shell script\n"""
            ]
        ]
        self.command_options = [
            {
                # "-a": ["-a", "a", "address", 0],
                # "--address": ["-a", "a", "address", 0],
                # "address": ["-a", "a", "address", 0],
                # "-p": ["-p", "p", "port", 1],
                # "--port": ["-p", "p", "port", 1],
                # "port": ["-p", "p", "port", 1]
            },
            {
                # "-t": ["-t", "t", "time", 1],
                # "--time": ["-t", "t", "time", 1],
                # "time": ["-t", "t", "time", 1],
                # "-s": ["-s", "s", "script", 2],
                # "--script": ["-s", "s", "script", 2],
                # "script": ["-s", "s", "script", 2]
            }
        ]

        if len(self.argv) == JnizzParser.command_idx + 1 \
                or self.argv[JnizzParser.command_idx + 1] == "help" \
                or self.argv[JnizzParser.command_idx + 1] == "--help" \
                or self.argv[JnizzParser.command_idx + 1] == "-h":
            self.print_help()
        elif self.argv[JnizzParser.command_idx + 1] == "init":
            self.result = [0,
                           {
                               "name": None
                           }
                           ]
            self.do_command(0),
        elif self.argv[JnizzParser.command_idx + 1] == "add-apk":
            self.result = [1,
                           {
                               "name": None
                           }
                           ]
            self.do_command(1)
        elif self.argv[JnizzParser.command_idx + 1] == "show":
            self.result = [2,
                           {
                               "name": None
                           }
                           ]
            self.do_command(2)
        else:
            print("jnizz: \'" + self.argv[JnizzParser.command_idx + 1] + "\' is not a jnizz-command. See \'jnizz --help\'")
            exit()

    def print_help(self):
        print("""
 usage: jnizz [help, -h, --help] COMMAND [ARGS]

 The most commonly used jnizz commands are:
   init <project-name>        initialize a JNI shower program source code
   add-apk <apk-name>         add targeted apk to fuzz
   show <apk-name>            show tombstones and exploitable possibility

 See 'jnizz COMMAND --help' for more information on a specific command.
""")
        exit()

    def do_command(self, command):
        if self.argv[JnizzParser.command_idx + 2] == "help" \
                or self.argv[JnizzParser.command_idx + 2] == "help" \
                or self.argv[JnizzParser.command_idx + 2] == "--help" \
                or self.argv[JnizzParser.command_idx + 2] == "-h":
            self.print_command_help(command)
        else:
            self.result[1]["name"] = self.argv[JnizzParser.command_idx + 2]
            for i in range(3, len(self.argv)):
                if command == 0 and (i & 1) == 1:
                    continue
                if command == 1 and (i & 1) == 0:
                    continue
                if self.argv[i] in self.command_options[command]:
                    self.get_value(command, i, self.command_options[command][self.argv[i]])
                else:
                    if self.argv[i][:JnizzParser.command_idx + 2] == "--":
                        chosen_option = "option \'" + self.argv[i][JnizzParser.command_idx + 2:] + "\'"
                    elif self.argv[i][:JnizzParser.command_idx + 1] == "-":
                        chosen_option = "switch \'" + self.argv[i][JnizzParser.command_idx + 1:] + "\'"
                    else:
                        chosen_option = "option \'" + self.argv[i] + "\'"
                    print("  Error: " + "unknown " + chosen_option)
                    self.print_command_help(command)

    def print_command_help(self, command, option=None):
        print("\n usage: jnizz " + self.command_help[command])
        if option is None:
            for i in self.command_options_help[command]:
                print(i)
        else:
            print(self.command_options_help[command][option])

        if command == 1:
            print(" See README.md to know how to query expression exactly\n")
        exit()

    def get_value(self, command, index, check_list):
        if len(self.argv) <= index + 1:
            if self.argv[index] == check_list[0]:
                chosen_option = "switch \'" + check_list[1] + "\'"
            else:
                chosen_option = "option \'" + check_list[2] + "\'"
            print("  Error: " + chosen_option + " requires a value")
            self.print_command_help(command, check_list[3])
        else:
            self.result[1][check_list[2]] = self.argv[index + 1]
