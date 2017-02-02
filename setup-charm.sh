#!/bin/bash
set -e

PKG_FLEX=flex
PKG_BISON=bison

if [ -f /etc/redhat-release ]
then
  # assumes this is a RedHat-based system.
  PACKAGE_MANAGER=yum
  PKG_SSL=openssl-devel
  PKG_GMP=gmp-devel
else
  # assumes `apt-get` if not a RedHat-based system, which is
  # probably not a good assumption.
  PACKAGE_MANAGER=apt-get
  PKG_SSL=libssl-dev
  PKG_GMP=libgmp-dev
  PKG_PYTHON=python3-dev
fi

[[ ! -z $PKG_FLEX ]] && sudo $PACKAGE_MANAGER -y install $PKG_FLEX
[[ ! -z $PKG_BISON ]] && sudo $PACKAGE_MANAGER -y install $PKG_BISON
[[ ! -z $PKG_SSL ]] && sudo $PACKAGE_MANAGER -y install $PKG_SSL
[[ ! -z $PKG_GMP ]] && sudo $PACKAGE_MANAGER -y install $PKG_GMP
[[ ! -z $PKG_PYTHON ]] && sudo $PACKAGE_MANAGER -y install $PKG_PYTHON

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
unzip -o dev.zip
pushd charm-dev
./configure.sh --python=$(which python3.5)
make
sudo make install
popd
popd

# Ensure that you are using pip3.5 for installation.
# Use link to refer pip3.5 using pip command: http://techglimpse.com/install-update-python-pip-linux-tutorial/
if [ -f "requirements.txt" ]; then
  pip install -r requirements.txt
fi

# configure dynamic linker run-time bindings
sudo ldconfig

