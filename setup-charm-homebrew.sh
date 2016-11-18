#!/bin/bash
set -e

brew install flex
brew install bison
brew install openssl
brew install gmp
brew install wget

# PBC
# Cleanup any old data
rm -fr ~/dev/pbc
mkdir -p ~/dev/pbc
pushd ~/dev/pbc
wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
tar xf pbc-0.5.14.tar.gz
pushd pbc-0.5.14
./configure
make
sudo make install
popd
popd

# Charm
# Cleanup any old data
rm -fr ~/dev/pbc
mkdir -p ~/dev/charm
pushd ~/dev/charm
wget https://github.com/JHUISI/charm/archive/dev.zip
unzip dev.zip
pushd charm-dev
./configure.sh --python=$(which python3.5)
make
sudo make install
popd
popd

# Ensure that you are using pip3.5 for installation.
# Use link to refer pip3.5 using pip command: http://techglimpse.com/install-update-python-pip-linux-tutorial/
pip3 install -r requirements.txt
