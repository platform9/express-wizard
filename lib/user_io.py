import sys
import time
import globals
import getpass
try:
    import queue
except ImportError:
    import Queue as queue
import threading


# timeout (seconds)
INPUT_TIMEOUT = 10

# function for keyboard input with timeout
def _input(msg, q):
    if sys.version_info[0] == 3:
        ra = input(msg)
    elif sys.version_info[0] == 2:
        ra = raw_input(msg)
    else:
        ra = raw_input(msg)
    if ra:
        q.put(ra)
    else:
        q.put("None")
    return


def _slp(tm, q):
    time.sleep(INPUT_TIMEOUT)
    q.put("Timeout")
    return

def wait_for_input(msg, time=10):
    q = queue.Queue()
    th = threading.Thread(target=_input, args=(msg, q,))
    tt = threading.Thread(target=_slp, args=(time, q,))

    th.start()
    tt.start()
    ret = None
    while True:
        ret = q.get()
        if ret:
            th._Thread__stop()
            tt._Thread__stop()
            return ret
    return ret


def read_kbd_timeout(user_prompt, default_value):
    user_in = wait_for_input(user_prompt)
    if user_in in ['Timeout','None']:
        sys.stdout.write("\n")
        sys.stdout.flush()
        return(default_value)
    return(user_in)


def read_kbd(user_prompt, allowed_values, default_value, flag_echo=True, disallow_null=True, input_timeout=False):
    input_is_valid = False
    while not input_is_valid:
        if sys.version_info[0] == 3:
            if flag_echo:
                if not input_timeout:
                    user_input = input("{} [{}]: ".format(user_prompt,default_value))
                else:
                    sys.stdout.flush()
                    user_input = read_kbd_timeout("{} [{}] (timeout={}): ".format(user_prompt,default_value,INPUT_TIMEOUT),default_value)
            else:
                user_input = getpass.getpass(prompt="{}: ".format(user_prompt), stream=None)
        if sys.version_info[0] == 2:
            if flag_echo:
                if not input_timeout:
                    user_input = raw_input("{} [{}]: ".format(user_prompt,default_value))
                else:
                    sys.stdout.flush()
                    user_input = read_kbd_timeout("{} [{}] (timeout={}): ".format(user_prompt,default_value,INPUT_TIMEOUT),default_value)
            else:
                user_input = getpass.getpass(prompt="{}: ".format(user_prompt), stream=None)

        if user_input == "":
            if disallow_null == True:
                if default_value != "":
                    user_input = default_value
                    input_is_valid = True
                else:
                    input_is_valid = False
            else:
                user_input = default_value
                input_is_valid = True
        else:
            if len(allowed_values) == 0:
                input_is_valid = True
            else:
                if user_input in allowed_values:
                    input_is_valid = True

    return(user_input)
