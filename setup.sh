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
cd ..

rm -rf libsodium-stable
rm libsodium-1.0.19.tar.gz

cd pam_enc_dir
./setup_pam.sh
cd ..

cd enc_dir_fuse
./setup_fuse.sh


if [[ -f /etc/pam.d/common-session ]] 
then 
  if [[ $(cat /etc/pam.d/common-session | grep pam_enc_dir.so | wc -l) -lt 1 ]] 
  then 
    echo "session optional pam_enc_dir.so" >> /etc/pam.d/common-session
  fi
  if [[ $(cat /etc/pam.d/common-auth | grep pam_enc_dir.so | wc -l) -lt 1 ]] 
  then 
    echo "auth optional pam_enc_dir.so" >> /etc/pam.d/common-auth
  fi
else
  if [[ $(cat /etc/pam.conf | grep "session optional pam_enc_dir.so" | wc -l) -lt 1 ]] 
  then 
    echo "common-session session optional pam_enc_dir.so" >> /etc/pam.conf
  fi
  if [[ $(cat /etc/pam.conf | grep "auth optional pam_enc_dir.so" | wc -l) -lt 1 ]] 
  then 
    echo "common-auth auth optional pam_enc_dir.so" >> /etc/pam.conf
  fi  
fi
