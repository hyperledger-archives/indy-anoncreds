#!/bin/sh

sudo apt-get install flex
sudo apt-get install bison
sudo apt-get install libssl-dev
sudo apt-get install libgmp-dev
sudo apt-get install python3.5-dev

# PBC
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
pip install -r requirements.txt