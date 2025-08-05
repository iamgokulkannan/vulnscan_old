import sys

colors = True
machine = sys.platform  # Determines the os running in the machine
if machine.lower().startswith(('os', 'win', 'darwin', 'ios')):
    colors = False  # The colors won't be visible in mac as well as windows
if not colors:
    end = red = white = green = yellow = run = bad = good = info = que = ''
    lightning = '⚡'
else:
    white = '\033[97m'      # Bright white
    green = '\033[92m'      # Bright green
    red = '\033[91m'        # Bright red
    yellow = '\033[93m'     # Bright yellow
    end = '\033[0m'         # Reset to default
    back = '\033[7;91m'     # Reverse mode with bright red background
    info = '\033[93m[!]\033[0m'   # Yellow [!]
    que = '\033[94m[?]\033[0m'    # Bright blue [?]
    bad = '\033[91m[-]\033[0m'    # Bright red [-]
    good = '\033[92m[+]\033[0m'   # Bright green [+]
    run = '\033[97m[~]\033[0m'    # Bright white [~]
    lightning = '\033[93;5m⚡\033[0m'  # Blinking yellow ⚡
