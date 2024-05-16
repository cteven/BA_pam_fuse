#!/bin/bash

sudo apt-get install libpam0g-dev
sudo apt-get install libfuse-dev -y


cd phc-winner-argon2
make
make install PREFIX=/usr 
make test

cd ..
wget "https://download.libsodium.org/libsodium/releases/libsodium-1.0.19.tar.gz"
tar -xvzf libsodium-1.0.19.tar.gz 
cd libsodium-stable
./configure
make && make install
ldconfig
rm -rf libsodium-stable
rm libsodium-1.0.19.tar.gz

cd ../pam_enc_dir
./setup_pam.sh

cd ../enc_dir_fuse
./setup_fuse.sh


if [[ -f /etc/pam.d/common-session ]] 
then 
  echo "session optional pam_enc_dir.so" >> /etc/pam.d/common-session
  echo "auth optional pam_enc_dir.so" >> /etc/pam.d/common-auth
fi
