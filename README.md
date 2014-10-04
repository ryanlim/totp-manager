# totp-manager

Time-based One-time Password (TOTP) manager.

## Overview

This is a Python based time-based one-time password (TOTP) manager,
similar to the Google Authenticator app on Android/iOS devices.

## Motivation

[This](http://forums.appleinsider.com/t/159337/google-authenticator-for-ios-update-wipes-all-on-board-account-data).

Since then, I've switched to Duo Mobile, but I had to wipe and restore my
phone once, and I ran into issues where the restore would not include my
TOTP keys. This meant that I had to go through the painful process of
reenrolling for two-factor authentication. Now imagine this process with
more than 2-3 accounts.

## Features:
* Support multiple accounts
* Support for 30-second TOTP codes
* The TOTP code is generated locally without Internet connectivity
* Your TOTP keys are encrypted (AES256) locally on your computer
* You can export out the TOTP keys as base32 strings, or scan them as QR codes on your phone's Google Authenticator app.

## Requirements
- Python 2.7 (it may work on other versions of Python)
- pycrypto
- oath
- tabulate
- qrcode

## Examples:

### Example an unencrypted totp-secrets.dat file.

You can encrypt this using the `encrypt` command, and decrypt it using
`decrypt`.

  [
      {
          "key": "FAKECODELOLOLFAKEFAKEFAKEDEMO234",
          "label": "account1@gmail.com",
          "provider": "Google"
      },
      {
          "key": "FAKECODELOLOLFAKEFAKEFAKEDEMO432",
          "label": "account2@gmail.com",
          "provider": "Google"
      },
      {
          "key": "LOLFAKELOL234567",
          "label": "account1@gmail.com",
          "provider": "Wordpress"
      }
  ]

### The `show` command:

This is the default command that displays your account and TOTP codes.

  Now: 2014-10-03 18:49:16 -0700
  TOTP tokens expires in 14 seconds.
  
  Provider    Label                 TOTP
  ----------  ------------------  ------
  Google      account1@gmail.com  151369
  Google      account2@gmail.com  985428
  Wordpress   account1@gmail.com  080348
  
  Control-C to exit.

### The `qrcode` command:

This command displays the QR code for importing the TOTP key to your phone.


## Attribution
* Joe Linoff - Implement openssl compatible AES-256 CBC mode encryption/decryption

## License
 
  Copyright (c) 2014 Ryan Lim
 
  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:
 
  The above copyright notice and this permission notice shall be included in
  all copies or substantial portions of the Software.
 
  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
  THE SOFTWARE.
