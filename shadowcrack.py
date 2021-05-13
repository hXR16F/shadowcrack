#!/usr/bin/python

# Programmed by hXR16F
# hXR16F.ar@gmail.com, https://github.com/hXR16F

import subprocess
from os import getcwd
from dialog import Dialog


def main():
    d = Dialog(dialog="dialog")

    f = open("/etc/shadow", "r")
    lines = f.readlines()
    f.close()

    # Analyzing all password protected users
    shadow_usernames = []
    for line in lines:
        if "$" in line:
            shadow_username = line.split(":")[0]
            shadow_usernames.append(shadow_username)

    # Select user
    choice_usernames, count, elements = [], 0, "["
    for i in shadow_usernames:
        count += 1
        choice_usernames.append([str(count), i])
        elements = elements + str(f"(\"({count})\", \"{choice_usernames[count - 1][1]}\"), ")

    elements = eval(elements[:-2] + "]")
    code, tag = d.menu("Select user you want to crack:", choices=elements, height=15, width=40)

    if code == d.OK:
        account_to_crack = str(shadow_usernames[int(tag[1:-1]) - 1])

        # Select wordlist
        code, wordlist = d.fselect(getcwd(), height=20, width=70)

        # Analyzing shadow file
        for line in lines:
            if "$" in line:
                if line.split(":")[0] == account_to_crack:
                    line_parsed = line.split(":")[1].split("$")
                    shadow_id, shadow_salt, shadow_hash = line_parsed[1], line_parsed[2], line_parsed[3]
                    original_hash = f"${shadow_id}${shadow_salt}${shadow_hash}"
                    break

        # Cracking using wordlist
        d.gauge_start(f"Cracking '{account_to_crack}' ...\n\nWordlist: '{wordlist}'", width=80, height=10)
        wordlist_length = int(subprocess.check_output(["wc", "-l", wordlist]).split()[0])

        with open(wordlist) as words:
            count, stopped, cracked = 0, False, False
            while True:
                count += 1
                wordlist_line = words.readline()
                if not wordlist_line:
                    break

                proc = subprocess.Popen(["openssl", "passwd", f"-{shadow_id}", "-salt", f"{shadow_salt}", f"{wordlist_line[:-1]}"], stdout=subprocess.PIPE)
                output = proc.communicate()
                if str(output[0], "utf-8")[:-1] == str(original_hash):
                    d.gauge_stop()
                    stopped, cracked = True, True
                    d.msgbox(f"Password found!\n\n'{account_to_crack}:{wordlist_line[:-1]}'", width=50, height=10)
                    subprocess.run(["clear"])
                    print(f"[shadowcrack] Password found! '{account_to_crack}:{wordlist_line[:-1]}'")
                    break

                d.gauge_update(int((count * 100) / wordlist_length))
            
            if not stopped:
                d.gauge_stop()
            
            if not cracked:
                d.msgbox(f"Password not found!", width=40, height=8)
                subprocess.run(["clear"])
                print(f"[shadowcrack] Password not found!")
    else:
        quit()


if __name__ == "__main__":
    main()
