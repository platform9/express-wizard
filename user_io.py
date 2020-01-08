import sys
import getpass

def read_kbd(user_prompt, allowed_values, default_value, flag_echo=True, disallow_null=True):
    input_is_valid = False
    while not input_is_valid:
        if sys.version_info[0] == 3:
            if flag_echo:
                user_input = input("{} [{}]: ".format(user_prompt,default_value))
            else:
                user_input = getpass.getpass(prompt="{}: ".format(user_prompt), stream=None)
        if sys.version_info[0] == 2:
            if flag_echo:
                user_input = raw_input("{} [{}]: ".format(user_prompt,default_value))
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


