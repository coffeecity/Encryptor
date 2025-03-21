# Requires pre.py for passgen
# pip install cryptography for functioning

################################## --- AES En/De cryptor --- ####################################

import os
import base64
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def caesar(text, step, alphabets):
    def shift(alphabet):
        return alphabet[int(step):] + alphabet[:int(step)]

    shifted_alphabets = tuple(map(shift, alphabets))
    joined_aphabets = ''.join(alphabets)
    joined_shifted_alphabets = ''.join(shifted_alphabets)
    table = str.maketrans(joined_aphabets, joined_shifted_alphabets)
    return text.translate(table)

# 🔹 Generate a Secure 256-bit AES Key from a Password
def derive_key_from_password(password, salt=None):
    if salt is None:
        salt = os.urandom(32)  # 256-bit salt for extra entropy
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key, salt

# 🔹 Encrypt Function (No Padding, AES-GCM)
def encrypt_aes_gcm(plaintext, password):
    # Generate a random salt (32 bytes for extra entropy)
    salt = os.urandom(32)  # 256-bit salt

    # Derive a strong 256-bit key
    key, _ = derive_key_from_password(password, salt)

    # Generate a 12-byte IV (Nonce) as required by AES-GCM
    iv = os.urandom(12)  # 12-byte IV (standard for AES-GCM)

    # Create AES-GCM cipher
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())

    # Generate a random AAD (Associated Data)
    aad = os.urandom(32)  # 32 bytes of random associated data

    # Encrypt the plaintext with the authentication tag
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(aad)
    ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()

    # Combine salt, IV, AAD, ciphertext, and tag
    encrypted_data = base64.b64encode(salt + iv + aad + ciphertext + encryptor.tag)

    return encrypted_data.decode()

# 🔹 Decrypt Function (AES-GCM without Padding)
def decrypt_aes_gcm(encrypted_data, password):
    # Decode from Base64
    encrypted_data = base64.b64decode(encrypted_data)

    # Extract Salt (32 bytes), IV (12 bytes), AAD (32 bytes), Ciphertext, and Tag
    salt = encrypted_data[:32]  # 32-byte salt
    iv = encrypted_data[32:44]  # 12-byte IV
    aad = encrypted_data[44:76]  # 32-byte AAD
    ciphertext = encrypted_data[76:-16]  # Ciphertext
    tag = encrypted_data[-16:]  # 16-byte Authentication Tag

    # Derive the key using the same salt
    key, _ = derive_key_from_password(password, salt)

    # Create cipher object
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    decryptor.authenticate_additional_data(aad)

    # Decrypt and verify authentication tag
    decrypted_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return decrypted_plaintext.decode()

def aes_encrypt():
    import string
    import base64
    from hashlib import sha256
    from time import sleep as s

    # Encrypt
    message = input('Enter your message: ')
    name = input("\nEnter your name: ")
    password = input('\nEnter First password: ')
    pass1 = encrypt_aes_gcm(message, password)
    #print("🔹 Pass 1:", pass1) Delete '#' for verbose logging

    hashd = sha256(pass1.encode('utf-8')).hexdigest()
    newmsg = pass1 + "-" + hashd

    message_bytes = newmsg.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')
    text = base64_message

    alphabets = (string.ascii_lowercase, string.ascii_uppercase, string.digits)
    stepval = input("\nShift Number?\n > ")  # Get Details for Ceasar
    toshift = caesar(str(text), step=int(stepval), alphabets=alphabets)  # Ceasar Shift String

    message = toshift
    password = input('\nEnter Second password: ')
    pass2 = encrypt_aes_gcm(message, password)
    #print("🔹 Pass 2:", pass2) Delete '#' for verbose logging

    message_bytes = name.encode('ascii')
    base64_bytes = base64.b64encode(message_bytes)
    base64_message = base64_bytes.decode('ascii')
    encname = base64_message
    message = str(encname) + ":" + pass2
    password = input('\nEnter your Const. password: ')
    pass3 = encrypt_aes_gcm(message, password)
    print("\n🔹 Ciphertext: ", pass3)
    input("\nPress Enter to Go Back...\n")
    start()



def aes_decrypt():
    # Decrypt
    import string
    import base64
    from hashlib import sha256
    from time import sleep as s


    encrypted_text = input('Enter your Ciphertext: ')
    password = input('Enter your Const. password: ')
    print(' ')
    try:
        pretext = decrypt_aes_gcm(encrypted_text, password)
    except:
        print('Invalid Const. password \n')
        encrypted_text = input('')
        print('\nExiting...')
        s(2)

    splitter1 = pretext.split(':')
    name = splitter1[0]
    base64_bytes = name.encode('ascii')
    message_bytes = base64.b64decode(base64_bytes)
    msgfrom = message_bytes.decode('ascii')
    encrypted_text = splitter1[1]

    password = input('Enter your Second password: ')
    try:
        decrypted_text = decrypt_aes_gcm(encrypted_text, password)
    except:
        print('Invalid password. \n')
        encrypted_text = ''
        print('\nExiting...')
        s(2)

    #print("🔹 Pass 2:", decrypted_text) Delete '#' for verbose logging
    text = decrypted_text


    alphabets = (string.ascii_lowercase, string.ascii_uppercase, string.digits)
    stepval = input("\nShift Count?\n")  # Get Details for Ceasar
    deshift = caesar(str(text), step=int(stepval), alphabets=alphabets)  # Ceasar Shift String


    try:
        base64_bytes = deshift.encode('ascii')
        message_bytes = base64.b64decode(base64_bytes)
        curmsg = message_bytes.decode('ascii')
    except:
        print('Invalid Shift. \n')
        deshift = ''
        print('Exiting...')
        s(2)

    splitter2 = curmsg.split('-')
    message = splitter2[0]
    hash = splitter2[1]

    check = sha256(message.encode('utf-8')).hexdigest()
    if check == hash:
        print('\nValid Hash!\n')
        encrypted_text = message
    else:
        print('Invalid Hash!')
        print('Info:\n(1) Message May have been tampered\nOR\n(2) Message may be corrupt.')
        encrypted_text = ''
        print('\n Quitting...')
        s(3)
        exit()

    password = input('Enter your First password: ')
    try:
        decrypted_text = decrypt_aes_gcm(encrypted_text, password)
    except:
        print('Invalid password. \n')
        encrypted_text = ''
        print('Exiting...')
        s(2)
    print('\nFrom: ', msgfrom)
    print("\n🔹 Message: ", decrypted_text)
    input("\nPress Enter to Go Back...\n")
    start()

################################## --- Password Generator --- ####################################


def passgen():
    from random import randrange as rr
    from random import choice as ch
    from time import sleep as s
    import pickle as pk
    import pre

    try: # Check if nltk is installed, if not ask user if they want to
        import nltk
        from nltk.corpus import brown
        from nltk import pos_tag
    except:
        print("It seems like you don't have nltk installed")
        print("Info: nltk is a dictionary used in this program so that the words to be used aren\'t limited \n")
        toinstall = input("Would you like to install it? (y/n) \n> ")
        if toinstall.lower() == "y": # Install nltk and also download word lists for later use
            import os
            os.system('cmd /k "@echo off & color a & echo [Python]: Installing NLTK Library & pip install nltk')
            nltk.download('brown')
            nltk.download('averaged_perceptron_tagger_eng')
        else:
            print("This script will not work without installing nltk \n")
            print("Quitting...")
            s(3)
            exit()

    class pt:
        @staticmethod
        def A():
            crs = ['@', '_', '!', '%', '^', '&', '>', '<', '?', '.', '#', '~', '-']
            x = rr(1, 13)
            return crs[x]

    # Word file caches
        def B(): # adverbs
            try:
                with open("av.pkl", "rb") as f:
                    av_ls = pk.load(f)
            except FileNotFoundError:
                av_ls = pre.av()
            av = ch(av_ls)
            return av

        def C(): # verbs
            try:
                with open("v.pkl", "rb") as f:
                    v_ls = pk.load(f)
            except FileNotFoundError:
                v_ls = pre.v()
            v = ch(v_ls)
            return v

        def D(): # midchar
            chs = ['(_)', '[_]', '{_}', '(-)', '[-]', '{-}', '(+)', '[+]', '{+}', '(=)', '[=]', '{=}', '(&)', '[&]', '{&}', '(%)', '[%]', '{%}']
            x = rr(0, 18) # Maximum Security
            return chs[x]

        def E(): #adjective
            try:
                with open("aj.pkl", "rb") as f:
                    aj_ls = pk.load(f)
            except FileNotFoundError:
                aj_ls = pre.aj()
            aj = ch(aj_ls)
            return aj

        def F(): #noun
            try:
                with open("n.pkl", "rb") as f:
                    n_ls = pk.load(f)
            except FileNotFoundError:
                n_ls = pre.n()
            n = ch(n_ls)
            return n

        def G(): #sidechar
            c1 = ['(#', '[#', '{#', '($', '[$', '{$', '(=', '[=', '{='] # Security LV.1 could be index 0-2 and Security LV 2 could be index 3-11
            mpr = {'(#': ')', '[#': ']', '{#': '}', '($': ')', '[$': ']', '{$': '}', '(=': ')', '[=': ']', '{=': '}'}
            a = rr(0, 8) # Maximum Security
            l = c1[a]
            r = mpr[l]
            return l, r

        def H():
            return rr(10000, 99999) #Maximum Security

    def joiner():
        a = pt.A()
        b = pt.B()
        c = pt.C()
        d = pt.D()
        e = pt.E()
        f = pt.F()
        lr = pt.G()
        gL = lr[0]
        g = pt.H()
        gR = lr[1]
        print(f'Your Password Is: {a}{b.title()}{c.title()}{d}{e.title()}{f.title()}{str(gL)}{g}{str(gR)}')

    joiner()
    joiner()
    input('\nPress enter to Go back...\n\n\n')
    start()

    ################################## --- Start of code --- ####################################
def start():

    print('- Welcome to Freds Encrypter! -\n')
    print('(1) Generate Passwords')
    print('(2) Encrypt Text')
    print('(3) Decrypt Text')
    a = input('\n > ')
    if a == '1':
        passgen()

    elif a == '2':
        aes_encrypt()

    elif a == '3':
        aes_decrypt()

start()