#!/usr/bin/python3
#coding: utf-8
#Author -> thespartoos

from pwn import *
import sys, os, subprocess
import signal, time
import threading, base64
import argparse


class Color:
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    END = '\033[0m'

def usage():
    fNombre = os.path.basename(__file__)
    ussage = 'python3 ' + fNombre + ' [-h] [-c CIPHERS] [-w WORDLIST] [-f FILE_ENCRYPTED] \n\n'
    ussage += '[+] Example:\n'
    ussage += '\t' 'python3 ' + fNombre + ' -c ciphers.txt -w dictionary.txt -f file.enc\n'
    return ussage

def arguments():
    parse = argparse.ArgumentParser(usage=usage())
    parse.add_argument('-c', dest='ciphers', type=str, help='List of Ciphers, default: ciphers.txt')
    parse.add_argument('-w', dest='wordlist', type=str, help='Wordlist')
    parse.add_argument('-f', dest='filename', type=str, help='File encrypted to bruteforce')
    return parse.parse_args()


def def_handler(sig, frame):
    print("\n[!] Saliendo...\n")
    sys.exit(0)

# CTRL + C
signal.signal(signal.SIGINT, def_handler)

banner = base64.b64decode("X19fX19fX18gICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgLl9fICAgICAgICAgICBfX19fX19fX19fX19fX19fX19fX18KXF9fX19fICBcIF9fX19fXyAgIF9fX18gICBfX19fICAgX19fX19fIF9fX19ffCAgfCAgICAgICAgICBcX19fX19fICAgXF8gICBfX19fXy8KIC8gICB8ICAgXF9fX18gXF8vIF9fIFwgLyAgICBcIC8gIF9fXy8vICBfX18vICB8ICAgIF9fX19fXyB8ICAgIHwgIF8vfCAgICBfXykgIAovICAgIHwgICAgXCAgfF8+ID4gIF9fXy98ICAgfCAgXF9fXyBcIFxfX18gXHwgIHxfXyAvX19fX18vIHwgICAgfCAgIFx8ICAgICBcICAgClxfX19fX19fICAvICAgX18vIFxfX18gID5fX198ICAvX19fXyAgPl9fX18gID5fX19fLyAgICAgICAgIHxfX19fX18gIC9cX19fICAvICAgCiAgICAgICAgXC98X198ICAgICAgICBcLyAgICAgXC8gICAgIFwvICAgICBcLyAgICAgICAgICAgICAgICAgICAgICBcLyAgICAgXC8gICAK").decode()

print(Color.BLUE + "\n" + banner + Color.END)

def main(ciphers, wordlist, filename):
    
    c = open(ciphers, "r")
        
    for cipher in c.readlines():
        
        first = cipher.split('\n', 1)[0]

        f = open(wordlist, "r", encoding='utf-8', errors='ignore')
        total_lines = len(f.readlines())
        #print(total_lines)
        f.close()

        p1 = log.progress("Fuerza bruta")

        counter = 0

        f = open(wordlist, "r", encoding='utf-8', errors='ignore')
        for password in f.readlines():
            
            password.strip('\n')

            p1.status("Probando el cifrado %s y contraseña [%d/%d]" % (first, counter, total_lines))
            
            cmd = subprocess.run(["/usr/bin/openssl %s -d -in %s -out archivo.txt -pass pass:%s" % (first, filename, password)], capture_output=True, text=True, shell=True)

            type = subprocess.run(['file', 'archivo.txt'], capture_output=True, text=True, input=cmd.stdout)


            if "archivo.txt: ASCII text" in type.stdout:
                password = password.strip('\n')
                p1.success("Crackeado con el cifrado " + Color.GREEN + f"{first}" + Color.END + " con la contraseña " + Color.END + Color.GREEN + f"{password}" + Color.END + Color.YELLOW + " ✓" + Color.END)
                sys.exit(0)
            
            counter += 1
        
        if "archivo.txt: ASCII text" not in type.stdout:
            p1.failure("No se ha podido crackear con el cifrado" + f" {first} " + Color.RED + "✘" + Color.END)

    if "archivo.txt: ASCII text" not in type.stdout:
        p1.failure("No se ha podido crackear la contraseña " + Color.RED + "✘" + Color.END)
        sys.exit(0)
    
if __name__ == '__main__':

    args = arguments()

    if len(sys.argv) < 6:
        print(usage())
        sys.exit(0)

    try:
        threading.Thread(target=main,args=(args.ciphers, args.wordlist, args.filename)).start()
    except Exception as e:
        log.error(str(e))
