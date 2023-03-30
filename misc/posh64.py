import sys
import base64

if __name__ == '__main__':
    print("[!] NOTE: escape \"")
    action = sys.argv[1]
    cmd = sys.argv[2]
    if action == 'enc':
        print(base64.b64encode(cmd.strip().encode('UTF-16LE')).decode())
    elif action == 'dec':
        print(base64.b64decode(cmd).decode('UTF-16LE'))