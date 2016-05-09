sudo apt-get install flex
sudo apt-get install bison
sudo apt-get install libssl-dev
sudo apt-get install libgmp-dev


##PBC
mkdir -p ~/dev/pbc
cd ~/dev/pbc
wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
tar xf pbc-0.5.14.tar.gz
cd pbc-0.5.14
./configure
make
sudo make install

##Charm
mkdir -p ~/dev/charm
cd ~/dev/charm
wget https://github.com/JHUISI/charm/archive/dev.zip
unzip dev.zip
cd charm-dev
./configure.sh --python=$(which python3.5)
make
sudo make install


pip install -r requirements.txt