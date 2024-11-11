mkdir Yara;
cd Yara;
sudo wget "https://github.com/VirusTotal/yara/archive/refs/tags/v4.2.0.tar.gz" -O yara.tar.gz;
sudo tar -zxf yara.tar.gz;
cd yara-4.2.0;
./bootstrap.sh;
./configure --enable-cuckoo --enable-magic --enable-python --with-crypto;
make;
sudo make install;