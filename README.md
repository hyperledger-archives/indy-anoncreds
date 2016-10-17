# AnonCreds: Anonymous credentials protocol implementation in python

This is a python implementation of the anonymous credentials ideas
developed by IBM Research (see https://idemix.wordpress.com/ and
http://www.research.ibm.com/labs/zurich/idemix/). We have built
some additional features for revocation.

Anonymous Credentials requires a cryptographic framework. We have tested it with charm-crypto. 
To install charm-crypto you just have to run `setup-charm.sh` script. It will require sudo privileges on the system.

# Installation on Mac

As a prerequisite first install http://brew.sh and OpenSLL https://solitum.net/openssl-os-x-el-capitan-and-brew

Then:

`git clone https://github.com/evernym/anoncreds.git`

`sh setup-charm-homebrew.sh`
