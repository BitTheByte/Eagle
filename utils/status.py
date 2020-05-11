from collections import namedtuple
from colorama import Fore
from colorama import init

ERROR   = 0
SUCCESS = 1
FAILED  = 2
WARNING = 3
UNKNOWN = 4
INFO    = 5
LOG     = 6

s2s = {
    ERROR:   'error',
    SUCCESS: 'success',
    FAILED:  'failed',
    WARNING: 'warning',
    UNKNOWN: 'unknown',
    INFO:    'info',
    LOG:     'logging'
}
s2c = {
    ERROR: Fore.RED,
    SUCCESS: Fore.GREEN,
    FAILED: Fore.RED,
    WARNING: Fore.YELLOW,
    UNKNOWN: Fore.LIGHTBLACK_EX,
    INFO: Fore.LIGHTBLACK_EX,
    LOG: Fore.LIGHTBLACK_EX
}

init(autoreset=True)
Result = namedtuple("Result","status msg request response")