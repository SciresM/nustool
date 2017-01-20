# nustool

nustool is a simple downloader and decryptor for titles on the Nintendo Update
Servers (NUS).

## Usage

```
Usage: nustool [-cmpr] [-k decrypted_key] [-K encrypted_key] [-V version] titleid

Downloads and optionally decrypts a title from NUS.

 -c              try to decrypt the title using the CETK key
 -k [key]        the titlekey to use to decrypt the contents
 -K [key]        the encrypted titlekey to use to decrypt the contents
 -h              print this help and exit
 -m              keep meta files (cetk, tmd); usable with make_cdn_cia
 -p              show progress bars
 -r              resume download
 -v              print nustool version and exit
 -V [version]    the version of the title to download; if not given,
                 the latest version will be downloaded

If none of -c, -k and -K are given, the raw encrypted contents
will be downloaded.

All files are downloaded into the current directory.
```

## Building

Copy `config.mk.template` to `config.mk` and then run `make`.

To build under windows, you will need to build [libcurl](https://curl.haxx.se/libcurl/), [libgpgerror](https://www.gnupg.org/(fr)/related_software/libgpg-error/index.html),
and [libgcrypt](https://www.gnu.org/software/libgcrypt/). I recommend using MinGW.

## Examples

### Downloading the raw encrypted contents of title 0004001b00010002

`$ nustool 0004001b00010002`

### Downloading and decrypting a system title

For system titles, you can pass `-c` to have them automatically be decrypted
using each system's common key. Note that this is not possible for 3DS system
titles as the required common keyX (or rather, the bootroms) has not yet been
dumped.

`$ nustool -c 0003000f484e4c45`

### Downloading and decrypting title 0006000012345678 with the encrypted titlekey 0123456789abcdef0123456789abcdef

`$ nustool -K 0123456789abcdef0123456789abcdef 0006000012345678`

### Downloading and decrypting title 0006000012345678 with the decrypted titlekey abcdef0123456789abcdef0123456789

`$ nustool -k abcdef0123456789abcdef0123456789 0006000012345678`

### Downloading and decrypting system title 00030017484e414a, displaying a progress bar for each file, version 1280

`$ nustool -cpV 1280 00030017484e414a`

## Licensing

This software is licensed under the terms of the ISC License.  
You can find a copy of the license in the LICENSE file.

