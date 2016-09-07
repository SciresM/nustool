# nustool

nustool is a simple downloader and decryptor for titles on the Nintendo Update
Servers (NUS).

## Usage

```
Usage: ./nustool [-c] [-k key] [-p] [-V version] titleid

Downloads and optionally decrypts a title from NUS.

 -c              try to decrypt the title using the CETK key
 -k [key]        the key to use to decrypt the contents; if not
                 given, the raw encrypted contents will be downloaded
 -h              print this help and exit
 -p              show progress bars
 -v              print nustool version and exit
 -V [version]    the version of the title to download; if not given,
                 the latest version will be downloaded

All files are downloaded into the current directory.
```

## Building

Copy `config.mk.template` to `config.mk` and then run `make`.

To build under windows, you will need to build [libcurl](https://curl.haxx.se/libcurl/), [libgpgerror](https://www.gnupg.org/(fr)/related_software/libgpg-error/index.html),
and [libgcrypt](https://www.gnu.org/software/libgcrypt/). I recommend using MinGW.

## Decryption Key

The decryption key must be a *decrypted* titlekey for the title you attempt to
download.

For system titles, you can pass `-c` to have them automatically be decrypted
using each system's common key. Note that this is not possible for 3DS system
titles as the required common keyX (or rather, the bootroms) has not yet been
dumped.

It can be obtained by decrypting the encrypted titlekey from a ticket with
AES-128-CBC using the common key as the AES key and the title ID in big endian
plus zero padding as the IV: For example, the IV for title ID 0004001b00010002
is `0004001B000100020000000000000000`.

## Licensing

This software is licensed under the terms of the ISC License.  
You can find a copy of the license in the LICENSE file.


