# Third-party notice

`pka2xml` is vendored from **cisco-pka-to-xml** by jeamxn:

- https://github.com/jeamxn/cisco-pka-to-xml
- MIT License (see `LICENSE` in this folder)

The decoder implements the Packet Tracer file format originally documented by
Mirco De Zorzi (`mircodz/pka2xml`).

The native `libtwofish.dll` is built from Niels Ferguson's reference C
implementation of the Twofish block cipher, which the upstream project vendors
under `vendor/twofish/` (also MIT-licensed).

Only the files needed by PKA Score Inspector are included here:

- `__init__.py` — decrypt/encrypt API
- `__main__.py` — optional command-line entry point
- `libtwofish.dll` — Windows x64 Twofish library
- `LICENSE` — upstream MIT license
