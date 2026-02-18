from pathlib import Path
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import scrypt
from Crypto.Random import get_random_bytes
import shutil
import getpass
import random
import sys
import subprocess

class Operations:
    def __init__(self) -> None:

        Path('vault').mkdir(parents=True, exist_ok=True)
        Path('vault\in').mkdir(parents=True, exist_ok=True)
        Path('vault\out').mkdir(parents=True, exist_ok=True)
        Path('vault\store').mkdir(parents=True, exist_ok=True)

        print("\033[H\033[J", end="")
        banner = '''

welcome to vaulted v1.0.

This application is meant for keeping your files secured.
It encrypts using an AES-256 encryption method.

        '''
        print(banner)
        self.password = getpass.getpass('please input your password to continue operations: ')
        print("\033[H\033[J", end="")

        inputAction = '99'
        while int(inputAction) != 0:
            inputAction = input('\nplease input the action number you want to perform\n\n0 - terminate\n1 - encrypt\n2 - decrypt\n3 - access vault\n\ninput:')
            print("\033[H\033[J", end="")

            if inputAction == '0':
                print("\033[H\033[J", end="")
            elif inputAction == '1':
                self.encrypt()
            elif inputAction == '2':
                self.decrypt()
            elif inputAction == '3':
                self.accessVault()

    def accessVault(self) -> None:
        if sys.platform == 'win32':
            subprocess.run(['explorer', Path('vault/in')])
        elif sys.platform == 'darwin':
            subprocess.run(['open', Path('vault/in')])
        elif sys.platform == 'linux' or sys.platform == 'linux2':
            subprocess.run(subprocess.open(['xdg-open', Path('vault/in')]))
        else: raise Warning('unsupported architecture detected, cannot open vault, please open it manually')

    def encrypt(self) -> None:
        pathFiles, pathDir = '', ''
        allSections = [ x.resolve() for x in list(Path('vault/in').rglob('*')) ]

        salt = get_random_bytes(16)
        with open(Path('vault/store/salt.bin'), 'wb') as f:
            f.write(salt)

        key = scrypt(self.password, salt, key_len=32, N=2**14, r=8, p=1)
      
        for x in list(allSections):
            if x.is_file():
                filenameNew = str(random.randint(10**11, 10**12-1))
                pathFiles += '\n' + filenameNew + '::' + str(x)
                
                with open(Path("vault/out/" + filenameNew), 'wb+') as f:
                    with open(Path(x), 'r') as g:

                        nonce = get_random_bytes(12)
                        cipher = AES.new(key, AES.MODE_GCM, nonce)
                        ciphertext, tag = cipher.encrypt_and_digest(g.read().encode('utf-8'))

                        f.write(nonce + ciphertext + tag)

                x.unlink()
                allSections.remove(x)

        with open(Path('vault/store/index.bin'), 'wb+') as f:
            data = ''.join(['\n' + str(x) for x in allSections]) + '\n-' + pathFiles
            
            nonce = get_random_bytes(12)
            cipher = AES.new(key, AES.MODE_GCM, nonce)
            ciphertext, tag = cipher.encrypt_and_digest(data.encode('utf-8'))

            f.write(nonce + ciphertext + tag)

        for x in list(allSections):
            if x.is_dir():
                pathDir += '\n' + str(x)

                shutil.rmtree(x)
                allSections.remove(x)


    def decrypt(self) -> None:
        pathFiles, pathDirs = [], []

        indexFile = Path('vault/store/index.bin')
        with open(indexFile, 'rb') as f:
            data = f.read()
            
            nonce = data[:12]
            tag = data[-16:]
            ciphertext = data[12:-16]

        with open(Path('vault/store/salt.bin'), 'rb') as f:
            salt = f.read()
        Path('vault/store/salt.bin').unlink()

        key = scrypt(self.password, salt, key_len=32, N=2**14, r=8, p=1)
        cipher = AES.new(key, AES.MODE_GCM, nonce)

        try:
            decryptedDataIndex = cipher.decrypt_and_verify(ciphertext, tag)
        except ValueError:
            print("\033[H\033[J", end="")
            print('Incorrect password for file decryption\n\n')
            input('press ENTER to exit')
            sys.exit(0)
        
        index = decryptedDataIndex.decode('utf-8').splitlines()[1:]

        pathDirs = index[:index.index('-')]
        pathFiles = index[index.index('-')+1:]

        for x in pathDirs:
            Path(x).mkdir()

        for x in pathFiles:
            mixedName, properName = x.split('::')

            with open(Path("vault/out/" + mixedName), 'rb') as f:
                with open(Path(properName), 'w') as g:

                    data = f.read()

                    nonce = data[:12]
                    tag = data[-16:]
                    ciphertext = data[12:-16]

                    cipher = AES.new(key, AES.MODE_GCM, nonce)
                    decryptedData = cipher.decrypt_and_verify(ciphertext, tag)

                    g.write(decryptedData.decode('utf-8'))

            Path("vault/out/" + mixedName).unlink()
        indexFile.unlink()


if __name__ == '__main__':
    x = Operations()