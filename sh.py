__name__ = "RSH"


import base64
import getpass
import hashlib
import os
import subprocess
import sys
import threading
from typing import List, NoReturn, Optional


os.chdir(rf"C:\Users\{getpass.getuser()}")


def equal_ignore_case(s1:str, s2:str):
    """
    Returns True if s1 and s2 is equal

    The main difference between this function and standard '==' operator is that this function is not case-sentesive

    Example:
    >>> print("equal") if equal_ignore_case("abc", "ABC") else "not equal"
    """
    s1 = s1.capitalize()
    s2 = s2.capitalize()
    if s1 == s2:
        return True
    else:
        return False

lineterm = "\n"
formated_path_var = os.environ["PATH"].strip(";").split(";")


def editor(file:Optional[str]):
    """Built-in editor"""
    if file is not None:
        try:
            f = open(file, "w+")
        except OSError:
            print("invaild file name")
    else:
        try:
            f = open(input("filename: "), "w+")
        except OSError:
            print("invaild file name")
    print("__________________________________________")
    content1 = input(f.readline())
    content2 = input(f.readline())
    content3 = input(f.readline())
    content4 = input(f.readline())
    content5 = input(f.readline())
    content6 = input(f.readline())
    content7 = input(f.readline())
    content8 = input(f.readline())
    content9 = input(f.readline())
    content10 = input(f.readline())
    content11 = input(f.readline())
    content12 = input(f.readline())
    content13 = input(f.readline())
    content14 = input(f.readline())
    content15 = input(f.readline())
    content = content1 + "\n" + content2 + "\n" + content3 + "\n" + content4 + "\n" + content5 + "\n" + content6 + "\n" +\
        content7 + "\n" + content8 + "\n" + content9 + "\n" + content10 + "\n" + content11 + "\n" + content12 + \
            "\n" + content13 + "\n" + content14 + "\n" + content15
    f.write(content) 


def sys_exit(code)->NoReturn:
    """Exit with message"""
    if int(code) > 0:
        if int(code) == 11:
            print("Exited with code {c}: Segmentation fault".format(c=code))
            exit(11)
        if int(code) == 15:
            print("Exited with code {c}: Terminated".format(c=code))
            exit(15)
        if int(code) == 22:
            print("Exited with code {c}: Aborted".format(c=code))
            exit(22)
        if int(code) == 2:
            print("Exited with code {c}: Interrupt".format(c=code))
            exit(2)
        if int(code) == 4:
            print("Exited with code {c}: Illegal instruction".format(c=code))
            exit(4)
        if int(code) == 8:
            print("Exited with code {c}: Floating point exception".format(c=code))
            exit(8)
        else:
            print("Exited with code {c}".format(c=code))
            exit()
    elif int(code) == 0:
        exit(0)
    else:
        print("Invaild exit code")
    

def upath(path:str):
    """Convert to Unix path"""
    path = path.replace("C:", "").replace("c:", "").replace("\\", "/")
    return path


def wpath(path:str):
    """Convert to Windows path"""
    path = ""+path.replace("/", "\\")
    return path


def seq2str(seq):
    s = ""
    for i in seq:
        s += i if i != "\n" else ""
    return s


def breaked_shell():
    _in = input("# ")
    sys_exit(15)


history = []
ps_path = r"c:\users\mama\downloads\portablegit\usr\bin\ps.exe"
lock = threading._RLock()
cmds = ["", "editor", "exit", "ls", "echo", "cd", "clear", "mkdir", "editor", "rm", "write-file", "lock", "cat", "psmgr",
"cmpf", "hash", "base64", "type", "kill", "tree", "breaked-shell", "history", "pwd"]



def main():
    """
    A core of shell
    """
    home_dir = fr"C:\Users\{getpass.getuser()}"
    if os.getcwd() == home_dir:
        prompt = "~@"+getpass.getuser()+"# "
    elif home_dir in os.getcwd():
        prompt = "~"+upath(os.getcwd().replace(home_dir, ""))+"@"+getpass.getuser()+"# "
    else:
        prompt = upath(os.getcwd())+"@"+getpass.getuser()+"# "
    stdin_raw = input(prompt)
    stdin = stdin_raw.strip().split()
    try:
        cmd = stdin[0]
        args = stdin[1:]
    except IndexError:
        cmd = ""
        args = ""
    if equal_ignore_case(cmd, "exit"):
        if len(args) == 1:
            sys_exit(args[0])
        else:
            sys_exit(0)
    if equal_ignore_case(cmd, "help"):
        print(
            "exit\n"+
            "help\n",
            "cd [dir]\n",
            "ls [-l] [dir]"
        ) 
    if equal_ignore_case(cmd, "cd"):
        if len(args) == 1:
            if args[0] == "~":
                os.chdir(home_dir)
            else:
                try:
                    os.chdir(wpath(args[0]))
                except OSError:
                    print("cd: error: directory not found")
        else:
            print("cd: error: invailid arguments")
    if equal_ignore_case(cmd, "echo"):
        if len(args) > 0:
            if args[0] == "$":
                print(1) if sys.exc_info()[2] else print(0)
            else:
                print(*args)
        else:
            print("")
    if equal_ignore_case(cmd, "ls"):
        if len(args) == 0:
            try:
                for r, d, f in os.walk(os.getcwd()):
                    for d2 in d:
                        print(d2+"/", end="\t")
                    for f2 in f:
                        print(f2, end="\t")
                    print()
                    break
            except OSError:
                print("ls: error: directory not found")
        elif len(args) == 1:
            if args[0] == "-l":
                try:
                    for r, d, f in os.walk(os.getcwd()):
                        print(f"total {len(d)+len(f)}")
                        for d2 in d:
                            print(d2+"/")
                        for f2 in f:
                            print(f2)
                        print()
                        break
                except OSError:
                    print("ls: error: directory not found")
            else:
                try:
                    for r, d, f in os.walk(args[0]):
                        for d2 in d:
                            print(d2+"/", end="\t")
                        for f2 in f:
                            print(f2, end="\t")
                        print()
                        break
                except OSError:
                    print("ls: error: directory not found")
        elif len(args) == 2:
            if args[0] == "-l":
                try:
                    for r, d, f in os.walk(args[1]):
                        print(f"total {len(d)+len(f)}")
                        for d2 in d:
                            print(d2+"/")
                        for f2 in f:
                            print(f2)
                        print()
                        break
                except OSError:
                    print("ls: error: directory not found")
            else:
                print(f"ls: error: invaild flag {args[0]}")
        else:
            print("ls: error: invaild arguments")
    if equal_ignore_case(cmd, "clear"):
        os.system("cls")
    if equal_ignore_case(cmd, "mkdir"):
        if len(args) == 1:
            os.mkdir(upath(args[0]))
        else:
            os.mkdir("New Folder")
    if equal_ignore_case(cmd, "editor"):
        print("sorry, editor is currenty unavalible")
        # editor doesn't working
        #if len(args) == 1:
        #    editor(args[0])
        #elif len(args) == 0:
        #    editor(None)
        #else:
        #    print("editor: error: invaild arguments", end=linesep)
    if equal_ignore_case(cmd, "rm"):
        if len(args) == 1:
            try:
                os.unlink(upath(args[0]))
            except OSError:
                print("rm: error: can not find file or dirctory")
        else:
            print("rm: error: invaild arguments")
    if equal_ignore_case(cmd, "write-file"):
        if len(args) > 1:
            file = args[0]
            content = args[1:]
            open(file, "w+", newline=lineterm).write(seq2str(content))
        if len(args) <= 1:
            print("write-file: error: invaild arguments")
    if equal_ignore_case(cmd, "lock"):
        if len(args) == 1:
            if args[0] == "aquire":
                lock.acquire(True)
            elif args[0] == "release":
                try:
                    lock.release()
                except RuntimeError:
                    print("lock: error: tryied to relesase un-aquired lock")
            elif args[0] == "mode":
                print("locked") if lock._block.locked() else print("unlocked")
            else:
                print("lock: error: invaild mode")
        else:
            print("lock: error: invaild arguments")
    if equal_ignore_case(cmd, "cat"):
        if len(args) == 1:
            file = args[0]
            if file == "stdin":
                print(input())
            else:
                try:
                    print(open(file).read())
                except OSError:
                    print("cat: error: cannot find file")
        else:
            print("cat: error: invaild arguments")
    if equal_ignore_case(cmd, "psmgr"):
        processes:list
        print([p for p in processes])
    if equal_ignore_case(cmd, "cmpf"):
        if len(args) == 3:
            if args[0] == "sha1":
                try:
                    f1_hash = hashlib.sha1(open(args[1], "rb").read()).hexdigest()
                    f2_hash = hashlib.sha1(open(args[2], "rb").read()).hexdigest()
                except OSError:
                    print("cmpf: error: file not found")
                else:
                    equal = True if f1_hash == f2_hash else False
                    print("File: %s, Hash: %s" % (args[0], f1_hash))
                    print("File: %s, Hash: %s" % (args[1], f2_hash))
                    print("Equal: %r" % equal)
            elif args[0] == "sha224":
                try:
                    f1_hash = hashlib.sha224(open(args[1], "rb").read()).hexdigest()
                    f2_hash = hashlib.sha224(open(args[2], "rb").read()).hexdigest()
                except OSError:
                    print("cmpf: error: file not found")
                else:
                    equal = True if f1_hash == f2_hash else False
                    print("File: %s, Hash: %s" % (args[0], f1_hash))
                    print("File: %s, Hash: %s" % (args[1], f2_hash))
                    print("Equal: %r" % equal)
            elif args[0] == "sha256":
                try:
                    f1_hash = hashlib.sha256(open(args[1], "rb").read()).hexdigest()
                    f2_hash = hashlib.sha256(open(args[2], "rb").read()).hexdigest()
                except OSError:
                    print("cmpf: error: file not found")
                else:
                    equal = True if f1_hash == f2_hash else False
                    print("File: %s, Hash: %s" % (args[0], f1_hash))
                    print("File: %s, Hash: %s" % (args[1], f2_hash))
                    print("Equal: %r" % equal)
            elif args[0] == "sha384":
                try:
                    f1_hash = hashlib.sha384(open(args[1], "rb").read()).hexdigest()
                    f2_hash = hashlib.sha384(open(args[2], "rb").read()).hexdigest()
                except OSError:
                    print("cmpf: error: file not found")
                else:
                    equal = True if f1_hash == f2_hash else False
                    print("File: %s, Hash: %s" % (args[0], f1_hash))
                    print("File: %s, Hash: %s" % (args[1], f2_hash))
                    print("Equal: %r" % equal)
            elif args[0] == "sha512":
                try:
                    f1_hash = hashlib.sha512(open(args[1], "rb").read()).hexdigest()
                    f2_hash = hashlib.sha512(open(args[2], "rb").read()).hexdigest()
                except OSError:
                    print("cmpf: error: file not found")
                else:
                    equal = True if f1_hash == f2_hash else False
                    print("File: %s, Hash: %s" % (args[0], f1_hash))
                    print("File: %s, Hash: %s" % (args[1], f2_hash))
                    print("Equal: %r" % equal)
            elif args[0] == "md5":
                try:
                    f1_hash = hashlib.md5(open(args[1], "rb").read()).hexdigest()
                    f2_hash = hashlib.md5(open(args[2], "rb").read()).hexdigest()
                except OSError:
                    print("cmpf: error: file not found")
                else:
                    equal = True if f1_hash == f2_hash else False
                    print("File: %s, Hash: %s" % (args[0], f1_hash))
                    print("File: %s, Hash: %s" % (args[1], f2_hash))
                    print("Equal: %r" % equal)
            else:
                print("cmpf: error: unsupported hash algorithm")
        else:
            print("cmpf: error: invaild arguments")
    if equal_ignore_case(cmd, "hash"):
        if len(args) >= 2:
            if args[0] == "md5":
                print(hashlib.md5(seq2str(args[1:]).encode()).hexdigest())
            elif args[0] == "sha1":
                print(hashlib.sha1(seq2str(args[1:]).encode()).hexdigest())
            elif args[0] == "sha224":
                print(hashlib.sha224(seq2str(args[1:]).encode()).hexdigest())
            elif args[0] == "sha256":
                print(hashlib.sha256(seq2str(args[1:]).encode()).hexdigest())
            elif args[0] == "sha384":
                print(hashlib.sha384(seq2str(args[1:]).encode()).hexdigest())
            elif args[0] == "sha512":
                print(hashlib.sha512(seq2str(args[1:]).encode()).hexdigest())
            else:
                print("hash: error: unsupported hash algorithm")
        else:
            print("hash: error: invaild arguments")
    if equal_ignore_case(cmd, "base64"):
        if len(args) >= 2:
            if args[0] == "encode":
                print((base64.encodestring(seq2str(args[1:]).encode())).decode().replace("\n", ""))
            elif args[0] == "decode":
                print((base64.decodestring(seq2str(args[1:]).encode())).decode().replace("\n", ""))
            else:
                print("hash: error: unsupported opoeration")
        else:
            print("hash: error: invaid arguments")
    if equal_ignore_case(cmd, "type"):
        if len(args) == 1:
            if args[0] in cmds:
                print("built-in command")
            else:
                print("external command")
        else:
            print("type: error: invaild arguments")
    if equal_ignore_case(cmd, "kill"):
        if len(args) == 1:
            try:
                os.kill(int(args[0]), 1) if isinstance(args[0], int) else print("kill: error: pid must be integer")
            except OSError as ose:
                print("kill: error: %s" % ose)
            except SystemError:
                print("kill: error: can't kill process %s" % args[0])
        else:
            print("kill: error: invaild arguments")
    if equal_ignore_case(cmd, "tree"):
        if len(args) == 0:
            print(subprocess.check_output("tree.com").decode("cp1250", "strict"))
        elif len(args) == 1:
            try:
                print(subprocess.check_output("tree.com %s").decode("utf-8", "ignore") % args[0])
            except OSError:
                print("tree: error: direcory not found")
        else:
            print("tree: error: invaild arguments")
    if equal_ignore_case(cmd, "breaked-shell"):
        breaked_shell()
    if equal_ignore_case(cmd, "history"):
        for i in history:
            print(i)
    if equal_ignore_case(cmd, "pwd"):
        print(upath(os.getcwd()))
    if (cmd.capitalize() or not cmd.capitalize()) in list(map(lambda x: x.capitalize(), cmds)):
        history.append(cmd)
    # not case-sentesive
    if not cmd.capitalize() in list(map(lambda x: x.capitalize(), cmds)):
        print(f"rsh: {cmd}: command not found")
    

def init():
    """Loop and Exceptions"""
    while True:
        try:
            main()
        except KeyboardInterrupt:
            continue
        except EOFError:
            continue


# driver code
if __name__ == "RSH":
    init()
