from .status import *
import datetime
import argparse
import sys
import re
from threading import Lock
lock = Lock()

banner_str = """
    .---.        .-----------
   /     \  __  /    ------
  / /     \(  )/    -----
 //////   ' \/ `   ---    Multipurpose vulnerability scanner
//// / // :    : ---                  v1.0b
/ /   /  /`    '--                  2019-2020
          //..\\           
     ====UU====UU====         - Loaded plugins: %i
         '//||\\`              - Worker(s): %i
           ''``
  Project Eagle - Main Engine
"""
statup_time = datetime.datetime.now().strftime("%d-%m-%Y.%H.%M.%S")
open(f"{sys.path[0]}/logs/{statup_time}.log", "a+").write(
    ' '.join(sys.argv) + "\n"
)

parser = argparse.ArgumentParser(description='[*] Project Eagle - Manual' )
parser.add_argument('--workers','-w',type=int, help='concurrent workers number default=5',default=5)
parser.add_argument(
    '--db',
    type=str,
    help='database file path',
    default=f"{sys.path[0]}/db/default.db.json",
)
parser.add_argument('-f','--file', help='targets file',type=str)
parser.add_argument('-v','--verbose', help='increase output verbosity',action="count",default=0)
parser.add_argument('-p','--ping',action='store_true', help='check availability of targets')
args = parser.parse_args()
if len(sys.argv) < 2:
    parser.print_help()
    exit(0)

def escape_ansi(line):
    ansi_escape = re.compile(r'(\x9B|\x1B\[)[0-?]*[ -/]*[@-~]')
    return ansi_escape.sub('', line)

def banner(plugins):
    print(banner_str % (plugins, args.workers))

def output(level,msg):
    with lock:
        level = '{color} {name}{reset}'.format(
            color = s2c[level],
            name  = s2s[level].upper(),
            reset = Fore.RESET
        ).ljust(19," ")

        msg  = "[%s] |%s| %s\n" % (datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"),level,msg)

        open(f"{sys.path[0]}/logs/{statup_time}.log", "a+").write(escape_ansi(msg))
        print(msg,end='')

def pprint(result):
    res   = result.ret
    host  = result.args[0]
    name  = result.channel.name

    if not res: return
    if name == 'ping':
        output(res.status, f"{res.msg}")
        return

    if args.verbose == 0 and res.status == SUCCESS:
        output(SUCCESS, f"plugin={name}, host={host}, msg={res.msg}")

    if args.verbose == 1 and res.status in [SUCCESS, WARNING]:
        output(res.status, f"plugin={name}, host={host}, msg={res.msg}")

    if args.verbose == 2 and res.status in [SUCCESS, WARNING, ERROR]:
        output(res.status, f"plugin={name}, host={host}, msg={res.msg}")

    if args.verbose == 3:
        output(
            res.status,
            f"plugin={name}, host={host}, status={s2s[res.status]}, msg={res.msg}",
        )
