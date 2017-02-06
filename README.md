# AnonCreds: Anonymous credentials protocol implementation in python

This is a python implementation of the anonymous credentials ideas developed by
IBM Research (see https://idemix.wordpress.com/ and
http://www.research.ibm.com/labs/zurich/idemix/). We have built some additional
features for revocation.

Anonymous Credentials requires a cryptographic framework. We have tested it with charm-crypto.
## Installation on Linux

### Prerequisites for RedHat-based Systems

- epel-release
- python-setuptools
- unzip
- wget

### Prerequisites for Debian-based Systems

### Command-line Install

```
git clone https://github.com/evernym/anoncreds.git
cd anoncreds
sh setup-charm.sh
```

## Installation on Mac

### Prerequisites

- [Homebrew](http://brew.sh)
- [OpenSSL](https://solitum.net/openssl-os-x-el-capitan-and-brew)

### Command-line Install

```
git clone https://github.com/evernym/anoncreds.git
cd anoncreds
sh setup-charm-homebrew.sh
```

## Installation on Windows

Please refer to the following guide on how to install charm-crypto on Windows x64:
[Windows Installation](windows-installation-guide.md)
