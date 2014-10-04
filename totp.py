#!/usr/bin/python

import hashlib
import os
import sys
import base64
import argparse
import getpass
import json
import pprint
import time
import curses
import signal
import urllib
import qrcode
import re
from Crypto.Cipher import AES
from oath import totp
from tabulate import tabulate
from operator import itemgetter

# Requires these dependencies:
# - pycrypto
# - oath
# - tabulate
# - qrcode

# This is how the unencrypted JSON payload looks like
'''
[
    {
        "provider": "Google",
        "label": "account@gmail.com",
        "key": "xxx"
    },
]
'''
# You would be able to decrypt the encrypted file using this command:
#  openssl enc -d -aes-256-cbc -base64 -md sha256 -in .totp-secrets.dat


SECRETS_FILE = os.path.join(os.environ['HOME'], '.totp-secrets.dat')
if 'TOTP_SECRETS_FILE' in os.environ:
    SECRETS_FILE = os.environ['TOTP_SECRETS_FILE']

if not os.path.isfile(SECRETS_FILE):
    SECRETS_FILE = None


class AES256_cbc:
    '''
    Implement openssl compatible AES-256 CBC mode encryption/decryption.

    This module provides encrypt() and decrypt() functions that are compatible
    with the openssl algorithms.

    This is basically a python encoding of my C++ work on the Cipher class
    using the Crypto.Cipher.AES class.

    URL: http://projects.joelinoff.com/cipher-1.1/doxydocs/html/
    '''
    # LICENSE
    #
    # Copyright (c) 2014 Joe Linoff
    #
    # Permission is hereby granted, free of charge, to any person obtaining a copy
    # of this software and associated documentation files (the "Software"), to deal
    # in the Software without restriction, including without limitation the rights
    # to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    # copies of the Software, and to permit persons to whom the Software is
    # furnished to do so, subject to the following conditions:
    #
    # The above copyright notice and this permission notice shall be included in
    # all copies or substantial portions of the Software.
    #
    # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    # IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    # FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    # AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    # LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    # OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    # THE SOFTWARE.

    VERSION='1.1'

    def __init__(self):
        pass

    # ================================================================
    # get_key_and_iv
    # ================================================================
    def get_key_and_iv(self, password, salt, klen=32, ilen=16, msgdgst='md5'):
        '''
        Derive the key and the IV from the given password and salt.

        This is a niftier implementation than my direct transliteration of
        the C++ code although I modified to support different digests.

        CITATION: http://stackoverflow.com/questions/13907841/implement-openssl-aes-encryption-in-python

        @param password  The password to use as the seed.
        @param salt      The salt.
        @param klen      The key length.
        @param ilen      The initialization vector length.
        @param msgdgst   The message digest algorithm to use.
        '''
        # equivalent to:
        #   from hashlib import <mdi> as mdf
        #   from hashlib import md5 as mdf
        #   from hashlib import sha512 as mdf
        mdf = getattr(__import__('hashlib', fromlist=[msgdgst]), msgdgst)
        password = password.encode('ascii','ignore')  # convert to ASCII

        try:
            maxlen = klen + ilen
            keyiv = mdf(password + salt).digest()
            tmp = [keyiv]
            while len(tmp) < maxlen:
                tmp.append( mdf(tmp[-1] + password + salt).digest() )
                keyiv += tmp[-1]  # append the last byte
                key = keyiv[:klen]
                iv = keyiv[klen:klen+ilen]
            return key, iv
        except UnicodeDecodeError:
            return None, None


    # ================================================================
    # encrypt
    # ================================================================
    def encrypt(self, password, plaintext, chunkit=True, msgdgst='md5'):
        '''
        Encrypt the plaintext using the password using an openssl
        compatible encryption algorithm. It is the same as creating a file
        with plaintext contents and running openssl like this:

        $ cat plaintext
        <plaintext>
        $ openssl enc -e -aes-256-cbc -base64 -salt \\
            -pass pass:<password> -n plaintext

        @param password  The password.
        @param plaintext The plaintext to encrypt.
        @param chunkit   Flag that tells encrypt to split the ciphertext
                         into 64 character (MIME encoded) lines.
                         This does not affect the decrypt operation.
        @param msgdgst   The message digest algorithm.
        '''
        salt = os.urandom(8)
        key, iv = self.get_key_and_iv(password, salt, msgdgst=msgdgst)
        if key is None:
            return None

        # PKCS#7 padding
        padding_len = 16 - (len(plaintext) % 16)
        padded_plaintext = plaintext + (chr(padding_len) * padding_len)

        # Encrypt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(padded_plaintext)

        # Make openssl compatible.
        # I first discovered this when I wrote the C++ Cipher class.
        # CITATION: http://projects.joelinoff.com/cipher-1.1/doxydocs/html/
        openssl_ciphertext = 'Salted__' + salt + ciphertext
        b64 = base64.b64encode(openssl_ciphertext)
        if not chunkit:
            return b64

        LINELEN = 64
        chunk = lambda s: '\n'.join(s[i:min(i+LINELEN, len(s))]
                                    for i in xrange(0, len(s), LINELEN))
        return chunk(b64)


    # ================================================================
    # decrypt
    # ================================================================
    def decrypt(self, password, ciphertext, msgdgst='md5'):
        '''
        Decrypt the ciphertext using the password using an openssl
        compatible decryption algorithm. It is the same as creating a file
        with ciphertext contents and running openssl like this:

        $ cat ciphertext
        # ENCRYPTED
        <ciphertext>
        $ egrep -v '^#|^$' | \\
            openssl enc -d -aes-256-cbc -base64 -salt -pass pass:<password> -in ciphertext
        @param password   The password.
        @param ciphertext The ciphertext to decrypt.
        @param msgdgst    The message digest algorithm.
        @returns the decrypted data.
        '''

        # unfilter -- ignore blank lines and comments
        filtered = ''
        for line in ciphertext.split('\n'):
            line = line.strip()
            if re.search('^\s*$', line) or re.search('^\s*#', line):
                continue
            filtered += line + '\n'

        # Base64 decode
        raw = base64.b64decode(filtered)
        assert( raw[:8] == 'Salted__' )
        salt = raw[8:16]  # get the salt

        # Now create the key and iv.
        key, iv = self.get_key_and_iv(password, salt, msgdgst=msgdgst)
        if key is None:
            return None

        # The original ciphertext
        ciphertext = raw[16:]

        # Decrypt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_plaintext = cipher.decrypt(ciphertext)

        padding_len = ord(padded_plaintext[-1])
        plaintext = padded_plaintext[:-padding_len]
        return plaintext


class TOTPManager:

    # LICENSE
    #
    # Copyright (c) 2014 Ryan Lim
    #
    # Permission is hereby granted, free of charge, to any person obtaining a copy
    # of this software and associated documentation files (the "Software"), to deal
    # in the Software without restriction, including without limitation the rights
    # to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    # copies of the Software, and to permit persons to whom the Software is
    # furnished to do so, subject to the following conditions:
    #
    # The above copyright notice and this permission notice shall be included in
    # all copies or substantial portions of the Software.
    #
    # THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    # IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    # FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    # AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    # LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    # OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
    # THE SOFTWARE.

    # Source: https://github.com/ryanlim/totp-manager/

    VERSION='1.0'

    MESSAGE_DIGEST_ALGO = 'sha256'

    def __init__(self, password):
        self.aes256 = AES256_cbc()
        self.password = password
        pass

    def encrypt(self, in_file, out_file):
        password_confirm = getpass.getpass("Retype password: ")
        if password != password_confirm:
            print "Password does not match!"
            sys.exit(1)
        if in_file == None:
            print "Paste in the JSON payload with unencrypted keys:"
            json_input = sys.stdin.readlines()
        else:
            with open(in_file, 'r') as in_file_:
                json_input = in_file_.readlines()
        raw_string = ''.join(json_input)

        if self.json_payload_validator(raw_string):
            unencrypted_secrets = json.loads(raw_string)


            encrypted_payload = self.aes256.encrypt(
                self.password,
                json.dumps(unencrypted_secrets, indent=4, sort_keys=True),
                msgdgst=self.MESSAGE_DIGEST_ALGO
            )

            if out_file == None:
                print(encrypted_payload)
            else:
                with open(out_file, 'w') as out_file_:
                    print "Writing encrypted payload to file %s" % out_file
                    out_file_.write(encrypted_payload)
        else:
            print "Failed to encrypt payload."

    def decrypt(self, secrets_file):
        encrypted_file = open(secrets_file, 'r')
        encrypted_payload = ''.join(encrypted_file.readlines())
        decrypted_payload_string = self.aes256.decrypt(
            self.password,
            encrypted_payload,
            msgdgst=self.MESSAGE_DIGEST_ALGO
        )

        if self.json_payload_validator(decrypted_payload_string):
            return json.loads(decrypted_payload_string)

    def json_payload_validator(self, json_payload_string):
        try:
            json_obj = json.loads(json_payload_string)
        except ValueError:
            print "This is not a valid JSON string."
            return False

        if not isinstance(json_obj, list):
            print "This is not a valid input (expected list, got %s):\n%s" % (type(json_payload), json_payload)
            return False

        for item in json_obj:
            if not isinstance(item, dict):
                print "This is not a valid input (expected dictionary):\n%s" % json_payload_string
                return False

            if set(['key', 'label', 'provider']) - set(item.keys()) != set():
                print "This is not a valid input (incorrect dictionary keys):\n%s" % json_payload_string
                return False

        return True

    def display_qrcodes(self, secrets_file):
        secrets = self.decrypt(secrets_file)
        qr = qrcode.QRCode()

        display = {}

        for secret in secrets:
            key_label = "%s: %s" % (
                secret['provider'], secret['label'])
            display[key_label] = 'otpauth://totp/%s:%s?secret=%s&issuer=%s' % \
                    (urllib.quote(secret['provider']),
                     urllib.quote(secret['label']), secret['key'],
                     urllib.quote(secret['provider']))

        for item in sorted(display.keys()):
            qr.clear()
            print "%s\n%s" % (item, display[item])
            qr.add_data(display[item])
            if args['format'] == 'ascii':
                qr.print_ascii()
            elif args['format'] == 'tty':
                qr.print_tty()
            print " " + "-"*75 + " "

    def handleSIGINT(self, signum, frame):
        curses.endwin()
        sys.exit(0)

    def show_all(self, secrets_file):
        screen = curses.initscr()# Init curses
        curses.noecho()
        curses.curs_set(0)
        screen.keypad(1)

        def show():
            output = ""
            output_list = []
            secrets = self.decrypt(secrets_file)
            for entry in secrets:
                decrypted_key = entry['key']

                try:
                    decrypted_key.decode('ascii')
                except UnicodeDecodeError:
                    curses.endwin()
                    print "Invalid password"
                    sys.exit(1)

                if len(decrypted_key) < 16:
                    decrypted_key = decrypted_key + '=' * (16-len(decrypted_key))
                elif len(decrypted_key) < 32 and len(decrypted_key) != 16:
                    decrypted_key = decrypted_key + '=' * (32-len(decrypted_key))

                secret = base64.b32decode(decrypted_key).encode('hex')

                output_list.append([entry['provider'], entry['label'], totp(secret)])

            output_list = sorted(output_list, key=itemgetter(0, 1))
            output += tabulate(output_list, ['Provider', 'Label', 'TOTP'])
            output += "\n"
            output += "\n"
            output += "Control-C to exit."
            screen.addstr(3, 0, output)
            screen.refresh()

        signal.signal(signal.SIGINT, self.handleSIGINT)

        show()
        while True:
            t=30
            expiration = (t-(int(time.time()) % t))
            screen.addstr(0, 0, "Now: %s" % time.strftime("%Y-%m-%d %H:%M:%S %z"))
            screen.addstr(1, 0, "TOTP tokens expires in %d second%s.  " % (expiration, "s"[expiration==1:]))
            screen.refresh()
            if expiration == 30:
                show()
            time.sleep(1)

        curses.endwin()



if __name__ == "__main__":
    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(dest='command')

    parser_encrypt = subparsers.add_parser(
        'encrypt',
        help="Encrypt a plain-text json file",
        description="""
        This command converts a plain-text JSON input into an AES256 encrypted
        output. If you do not specify the --in-file argument, we will read your
        JSON input from stdin. If you do not specify the --out-file argument,
        the encrypted payload will be displayed in stdout.
        """
    )
    parser_encrypt.add_argument('--in-file', action='store',
                                help="Read plain-text input file. Default: stdin")
    parser_encrypt.add_argument('--out-file', action='store',
                                help="Save encrypted data file. Default: stdout")

    parser_decrypt = subparsers.add_parser(
        'decrypt',
        help="Decrypt an encrypted file",
        description="""
        This command converts an en encrypted secrets file into a plain-text JSON.
        If you do not specify the --in-file argument, %s will be used. If you
        do not specify the --out-file argument, the plain-text JSON will be
        displayed in stdout.
        """ % (SECRETS_FILE)
    )
    parser_decrypt.add_argument('--in-file', action='store',
                                default=SECRETS_FILE,
                                help="Read encrypted input file.")
    parser_decrypt.add_argument('--out-file', action='store',
                        help="Save decrypted file. Default: stdout.")

    parser_show = subparsers.add_parser(
        'show',
        help="Show the TOTP tokens (default mode)",
        description="""
        This command displays the time based one-time-password generated from the
        secrets in your secrets file. If you do not specify the --in-file
        argument, this will default to $HOME/.totp-secrets.dat, otherwise it will
        use the TOTP_SECRETS_FILE environment variable.
        """)
    parser_show.add_argument('--in-file', action='store',
                             default=SECRETS_FILE,
                             help="Read encrypted input file.")

    parser_qrcodes = subparsers.add_parser(
        'qrcodes',
        help="Display the secret QR codes",
        description="""
        This command display the secret QR codes as URIs so that it may be quickly
        imported to a mobile device. If you do not specify the --in-file argument,
        this will default to $HOME/.totp-secrets.dat, otherwise it will use the
        TOTP_SECRETS_FILE environment variable.
        """)
    parser_qrcodes.add_argument('--in-file', action='store',
                               default=SECRETS_FILE,
                               help="Read encrypted input file.")
    parser_qrcodes.add_argument('--format', action='store',
                               default='tty',
                               choices=['tty', 'ascii'],
                               help="""Display qrcodes as TTY colors or ASCII
                                characters. Default: tty""")

    if (len(sys.argv) < 2):
        args = vars(parser.parse_args(['show']))
    else:
        args = vars(parser.parse_args(sys.argv[1:]))

    if args['command'] in ('decrypt', 'show', 'qrcodes'):
        SECRETS_FILE = args['in_file']
        if not SECRETS_FILE or not os.path.isfile(SECRETS_FILE):
            print "No secrets file provided, or defaults do not exist."
            sys.exit(1)
        print "Reading secrets from: %s" % args['in_file']

    password = ""
    try:
        password = getpass.getpass()
    except KeyboardInterrupt:
        print
        sys.exit(1)
        pass

    secret = hashlib.sha256(password).digest()
    cipher = AES.new(secret)

    totpmanager = TOTPManager(password)

    if args['command'] == 'encrypt':
        totpmanager.encrypt(args['in_file'], args['out_file'])
    elif args['command'] == 'decrypt':
        if args['out_file'] == None:
            print json.dumps(totpmanager.decrypt(SECRETS_FILE), indent=4, sort_keys=True)
        else:
            with open(args['out_file'], 'w') as out_file:
                print "Writing secrets to %s" % args['out_file']
                json.dump(totpmanager.decrypt(SECRETS_FILE), out_file, indent=4, sort_keys=True)
    elif args['command'] == 'qrcodes':
        totpmanager.display_qrcodes(SECRETS_FILE)
    else:
        totpmanager.show_all(SECRETS_FILE)
