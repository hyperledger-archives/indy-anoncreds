
## Before you Continue

If you haven't done so already, please visit the main resource for all things "Indy" to get acquainted with the code base, helpful resources, and up-to-date information: [Hyperledger Wiki-Indy](https://wiki.hyperledger.org/projects/indy).

# AnonCreds: Anonymous credentials protocol implementation in python
[![Build Status](https://ci.evernym.com/buildStatus/icon?job=Anoncreds/master)](https://ci.evernym.com/view/Core/job/Anoncreds/job/master/)

This is a python implementation of the anonymous credentials ideas developed by
IBM Research (see https://idemix.wordpress.com/ and
http://www.research.ibm.com/labs/zurich/idemix/). We have built some additional
features for revocation.

Anonymous credential technology is used to exchange claims and proofs,
increasing trust between parties in a [self-sovereign identity ecosystem](https://sovrin.org).
These claims and proofs are not recorded on a distributed ledger like the one provided
by Indy--but they rely on public keys, accumulators, and revocation registries published
on the ledger, and they dramatically increase privacy for participants. Hence their
inclusion with the Indy family of projects.

This particular codebase will soon be superseded by an implentation that is easier to
call (has cleaner interfaces) in [Indy SDK](https://github.com/hyperledger/indy-sdk).
Both implementations use the same underlying primitives, and implement the same
algorithms.

If you want to log bugs or examine the backlog for anoncreds, we recommend that you use
[Hyperledger's Jira](https://jira.hyperledger.org) and use the INDY-SDK project.

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
git clone https://github.com/hyperledger/indy-anoncreds.git
cd indy-anoncreds
sh setup-charm.sh
```

## Installation on Mac

### Prerequisites

- [Homebrew](http://brew.sh)
- [OpenSSL](https://solitum.net/openssl-os-x-el-capitan-and-brew)

### Command-line Install

```
git clone https://github.com/hyperledger/indy-anoncreds.git
cd indy-anoncreds
sh setup-charm-homebrew.sh
```

## Installation on Windows

Please refer to the following guide on how to install charm-crypto on Windows x64:
[Windows Installation](windows-installation-guide.md)
