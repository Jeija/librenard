# `librenard` - Sigfox Protocol Library

<img src="logo.svg" align="right" width="30%"/>

<p align="center">
    <a href="https://librenard.readthedocs.io"><img src="https://readthedocs.org/projects/librenard/badge/?version=latest" alt="ReadTheDocs"></a>
    <a href="https://circleci.com/gh/Jeija/librenard"><img src="https://circleci.com/gh/Jeija/librenard.svg?style=shield&circle-token=812dca1abdf804f91805e8932f8eb0519aefd99e" alt="CircleCI"></a>
</p>

`librenard` is a portable library written in the C programming language that implements [Sigfox](https://www.sigfox.com/) uplink and downlink frame encoding and decoding. It aims to be an open source replacement for [Sigfox's proprietary device library](https://build.sigfox.com/sigfox-library-for-devices). It can be used in conjuction with the CLI frontend [`renard`](https://github.com/Jeija/renard) and the SDR physical layer [`renard-phy`](https://github.com/Jeija/renard-phy) or be embedded in your custom IoT application on any microcontroller platform. For instance, [`renard-phy-s2lp`](https://github.com/Jeija/renard-phy-s2lp) can be used to build a completely open-source Sigfox device based on `librenard` and STMicroelectronics' S2-LP ultra-low power transceiver chip.

It has been tested on many platforms including Linux, macOS, Android (x86 and ARM), STM32L0 and ESP32 and should also be portable to other operating systems and various microcontroller platforms.

## Installation and Compilation
* Clone this repository:
```
git clone https://github.com/Jeija/librenard
```

* `librenard` has no dependencies other than a working compiler and `make`. Compile using:
```
cd librenard
make
```

* This generates the static library file `librenard.a` which can be linked to your application or the `renard` CLI frontend.

## Embedding
`librenard` is designed to be statically linked with your own application, so that it can be embedded into microcontroller code or into other tools.
For using `librenard` you will have to tell your compiler about the path to the `librenard.a` static library file and about the path to the header includes.

Most compilers (shown here: `gcc`) use the following options to specify library and header locations:
```
gcc -I librenard/src <your_C_sources> librenard/librenard.a -o out
```

See [`renard`](https://github.com/Jeija/renard) for an example of how to incorporate `librenard` into your application and build system.
Please refer to the [documentation](#documentation) for information on how to include the `librenard` headers in your source code and for information on how to use the `librenard` functions.

## Documentation
Up-to-date documentation is always available online at [Read the Docs](https://librenard.readthedocs.io).

You can build the documentation yourself by following these steps:
* Clone the `librenard` if you have not already (see [Installation and Compilation](#installation-and-compilation))
* `librenard` uses [sphinx](http://www.sphinx-doc.org), [doxygen](http://www.doxygen.org/) and [breathe](https://github.com/michaeljones/breathe) for documentation. You will need to install these dependencies.
* Generate HTML documentation files:
```
cd librenard/doc
make html
```
* Open `doc/_build/html/index.html` in a web browser