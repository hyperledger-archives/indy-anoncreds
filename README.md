# AnonCreds: Anonymous credentials protocol implementation in python

This is a python implementation of the anonymous credentials ideas developed by
IBM Research (see https://idemix.wordpress.com/ and
http://www.research.ibm.com/labs/zurich/idemix/). We have built some additional
features for revocation.

Anonymous Credentials requires a cryptographic framework. We have tested it
with charm-crypto.  To install charm-crypto you just have to run
`setup-charm.sh` script. It will require sudo privileges on the system.

# Installation on Linux

## Prerequisites for RedHat-based Systems

- epel-release
- python-setuptools
- unzip
- wget

## Prerequisites for Debian-based Systems

## Command-line Install

```
git clone https://github/evernym/anoncreds.git
sh setupt-charm.sh
```

# Installation on Mac

## Prerequisites

- [Homebrew](http://brew.sh)
- [OpenSSL](https://solitum.net/openssl-os-x-el-capitan-and-brew)

## Command-line Install

```
git clone https://github.com/evernym/anoncreds.git
sh setup-charm-homebrew.sh
```
