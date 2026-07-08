"""
AURORA C2 - Command type mapping.
"""

CMD_TYPE_MAP = {
    "shell": 78,
    "exec": 12,
    "exit": 3,
    "sleep": 4,
    "cd": 5,
    "pwd": 39,
    "ls": 53,
    "download": 11,
    "upload": 10,
    "whoami": 27,
    "ps": 32,
    "kill": 33,
    "jobs": 41,
    "jobkill": 42,
    "ifconfig": 200,
    "portscan": 89,
    "mkdir": 54,
    "drives": 55,
    "rm": 56,
    "cp": 73,
    "mv": 74,
    "setenv": 72,
    "inline-execute": 100,
    "dllinject": 202,
    "execute-assembly": 203,
}

CMD_TYPE_NAMES = {v: k for k, v in CMD_TYPE_MAP.items()}
