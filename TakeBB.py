import itertools
import sys, os
import string
import datetime
import bcrypt
import random
import threading
from binascii import unhexlify
from Crypto.Cipher import AES
from simplebitcoinfuncs import normalize_input, b58d, hexstrlify, dechex, privtopub, compress, pubtoaddress, b58e, multiplypriv
from simplebitcoinfuncs.ecmath import N
from simplebitcoinfuncs.hexhashes import hash256

def red(text):
    os.system(""); faded = ""
    for line in text.splitlines():
        green = 250
        for character in line:
            green -= 5
            if green < 0:
                green = 0
            faded += (f"\033[38;2;255;{green};0m{character}\033[0m")
        faded += "\n"
    return faded

def blue(text):
    os.system(""); faded = ""
    for line in text.splitlines():
        green = 0
        for character in line:
            green += 3
            if green > 255:
                green = 255
            faded += (f"\033[38;2;0;{green};255m{character}\033[0m")
        faded += "\n"
    return faded

def water(text):
    os.system(""); faded = ""
    green = 10
    for line in text.splitlines():
        faded += (f"\033[38;2;0;{green};255m{line}\033[0m\n")
        if not green == 255:
            green += 15
            if green > 255:
                green = 255
    return faded
    
def purple(text):
    os.system("")
    faded = ""
    down = False

    for line in text.splitlines():
        red = 40
        for character in line:
            if down:
                red -= 3
            else:
                red += 3
            if red > 254:
                red = 255
                down = True
            elif red < 1:
                red = 30
                down = False
            faded += (f"\033[38;2;{red};0;220m{character}\033[0m")
    return faded
    
def simple_aes_decrypt(msg, key):
    assert len(msg) == 16
    assert len(key) == 32
    cipher = AES.new(key, AES.MODE_ECB)
    msg = hexstrlify(cipher.decrypt(msg))
    while msg[-2:] == '7b':  # Can't use rstrip for multiple chars
        msg = msg[:-2]
    for i in range((32 - len(msg)) // 2):
        msg = msg + '7b'
    assert len(msg) == 32
    return unhexlify(msg)


def bip38decrypt(password, encpriv, outputlotsequence=False):
    password = normalize_input(password, False, True)
    encpriv = b58d(encpriv)
    assert len(encpriv) == 78
    prefix = encpriv[:4]
    assert prefix == '0142' or prefix == '0143'
    flagbyte = encpriv[4:6]
    if prefix == '0142':
        salt = unhexlify(encpriv[6:14])
        msg1 = unhexlify(encpriv[14:46])
        msg2 = unhexlify(encpriv[46:])
        scrypthash = hexstrlify(bcrypt.kdf(password=password, salt=salt, desired_key_bytes=64, rounds=16384))
        key = unhexlify(scrypthash[64:])
        msg1 = hexstrlify(simple_aes_decrypt(msg1, key))
        msg2 = hexstrlify(simple_aes_decrypt(msg2, key))
        half1 = int(msg1, 16) ^ int(scrypthash[:32], 16)
        half2 = int(msg2, 16) ^ int(scrypthash[32:64], 16)
        priv = dechex(half1, 16) + dechex(half2, 16)
        if int(priv, 16) == 0 or int(priv, 16) >= N:
            if outputlotsequence:
                return False, False, False
            else:
                return False
        pub = privtopub(priv, False)
        if flagbyte in COMPRESSION_FLAGBYTES:
            privcompress = '01'
            pub = compress(pub)
        else:
            privcompress = ''
        address = pubtoaddress(pub, '00')
        try:
            addrhex = hexstrlify(address)
        except:
            addrhex = hexstrlify(bytearray(address, 'ascii'))
        addresshash = hash256(addrhex)[:8]
        if addresshash == encpriv[6:14]:
            priv = b58e('80' + priv + privcompress)
            if outputlotsequence:
                return priv, False, False
            else:
                return priv
        else:
            if outputlotsequence:
                return False, False, False
            else:
                return False
    else:
        owner_entropy = encpriv[14:30]
        enchalf1half1 = encpriv[30:46]
        enchalf2 = encpriv[46:]
        if flagbyte in LOTSEQUENCE_FLAGBYTES:
            lotsequence = owner_entropy[8:]
            owner_salt = owner_entropy[:8]
        else:
            lotsequence = False
            owner_salt = owner_entropy
        salt = unhexlify(owner_salt)
        prefactor = hexstrlify(scrypt.hash(password, salt, 16384, 8, 8, 32))
        if lotsequence is False:
            passfactor = prefactor
        else:
            passfactor = hash256(prefactor + owner_entropy)
        if int(passfactor, 16) == 0 or int(passfactor, 16) >= N:
            if outputlotsequence:
                return False, False, False
            else:
                return False
        passpoint = privtopub(passfactor, True)
        password = unhexlify(passpoint)
        salt = unhexlify(encpriv[6:14] + owner_entropy)
        encseedb = hexstrlify(scrypt.hash(password, salt, 1024, 1, 1, 64))
        key = unhexlify(encseedb[64:])
        tmp = hexstrlify(simple_aes_decrypt(unhexlify(enchalf2), key))
        enchalf1half2_seedblastthird = int(tmp, 16) ^ int(encseedb[32:64], 16)
        enchalf1half2_seedblastthird = dechex(enchalf1half2_seedblastthird, 16)
        enchalf1half2 = enchalf1half2_seedblastthird[:16]
        enchalf1 = enchalf1half1 + enchalf1half2
        seedb = hexstrlify(simple_aes_decrypt(unhexlify(enchalf1), key))
        seedb = int(seedb, 16) ^ int(encseedb[:32], 16)
        seedb = dechex(seedb, 16) + enchalf1half2_seedblastthird[16:]
        assert len(seedb) == 48  # I want to except for this and be alerted to it
        try:
            factorb = hash256(seedb)
            assert int(factorb, 16) != 0
            assert not int(factorb, 16) >= N
        except:
            if outputlotsequence:
                return False, False, False
            else:
                return False
        priv = multiplypriv(passfactor, factorb)
        pub = privtopub(priv, False)
        if flagbyte in COMPRESSION_FLAGBYTES:
            privcompress = '01'
            pub = compress(pub)
        else:
            privcompress = ''
        address = pubtoaddress(pub, '00')
        try:
            addrhex = hexstrlify(address)
        except:
            addrhex = hexstrlify(bytearray(address, 'ascii'))
        addresshash = hash256(addrhex)[:8]
        if addresshash == encpriv[6:14]:
            priv = b58e('80' + priv + privcompress)
            if outputlotsequence:
                if lotsequence is not False:
                    lotsequence = int(lotsequence, 16)
                    sequence = lotsequence % 4096
                    lot = (lotsequence - sequence) // 4096
                    return priv, lot, sequence
                else:
                    return priv, False, False
            else:
                return priv
        else:
            if outputlotsequence:
                return False, False, False
            else:
                return False


def testPassword(pwd):
    try:
        if bip38decrypt(pwd, encryptedSecret) != False:
            pwdLenth = 22 + len(pwd)
            print("\n\n" + "#" * pwdLenth + "\n## PASSWORD FOUND: {pwd} ##\n".format(pwd=pwd) + "#" * pwdLenth + "\n")
            global flag
            flag = 1
    except:
        pass
    finally:
        td.release()


if __name__ == '__main__':
    mizogg= f'''
                      ___            ___
                     (o o)          (o o)
                    (  V  ) MIZOGG (  V  )
                    --m-m------------m-m--
                  © mizogg.co.uk 2018 - 2023
                    Take Bobbys Bitcoin

                    VIP PROJECT Mizogg 
                 
    {red(f"[>] Running with Python {sys.version_info[0]}.{sys.version_info[1]}.{sys.version_info[2]}")}

                    Take Bobbys Bitcoin
'''
    print(water(mizogg), end="")

    COMPRESSION_FLAGBYTES = ['20', '24', '28', '2c', '30', '34', '38', '3c', 'e0', 'e8', 'f0', 'f8']
    LOTSEQUENCE_FLAGBYTES = ['04', '0c', '14', '1c', '24', '2c', '34', '3c']

    encryptedSecret = "6PnQmAyBky9ZXJyZBv9QSGRUXkKh9HfnVsZWPn4YtcwoKy5vufUgfA3Ld7"
       

    threadNum = 32

    pwdCharacters = string.ascii_uppercase + string.digits
    maxCombination = 20 
    maxLength = 23 
    positions = [4, 9, 14, 19]

    td = threading.BoundedSemaphore(int(threadNum))
    threadlist = []

    print(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    num = 0
    flag = 0
    password_option = input(purple("Enter 1 for sequential or 2 for random password generation: ").lower() + "\033[38;2;148;0;230m")
    if password_option == '1':
        for pwd in itertools.product(pwdCharacters, repeat=maxCombination):
            if flag == 1:
                break

            password = "".join(pwd)
            if len(password) <= int(maxLength):
                formatted_pwd = list(password)
                for pos in positions:
                    formatted_pwd.insert(pos, '-')
                formatted_pwd = ''.join(formatted_pwd)

                num += 1
                msg = 'Test Password {num} , {password}'.format(num=num, password=formatted_pwd)
                sys.stdout.write('\r' + msg)
                sys.stdout.flush()
                td.acquire()
                t = threading.Thread(target=testPassword, args=(formatted_pwd,))
                t.start()
                threadlist.append(t)
        for x in threadlist:
            x.join()

        print(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    elif password_option == '2':
        while True:
            if flag == 1:
                break

            password = ''.join(random.sample(pwdCharacters, maxCombination))
            if len(password) <= int(maxLength):
                formatted_pwd = list(password)
                for pos in positions:
                    formatted_pwd.insert(pos, '-')
                formatted_pwd = ''.join(formatted_pwd)

                num += 1
                msg = 'Test Password {num} , {password}'.format(num=num, password=formatted_pwd)
                sys.stdout.write('\r' + msg)
                sys.stdout.flush()
                td.acquire()
                t = threading.Thread(target=testPassword, args=(formatted_pwd,))
                t.start()
                threadlist.append(t)
        for x in threadlist:
            x.join()

        print(datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
        
    else:
        print("Invalid option. Please enter '1' or '2'.")