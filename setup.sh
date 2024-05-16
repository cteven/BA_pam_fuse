#!/bin/bash

sudo apt-get install libpam0g-dev
sudo apt-get install libfuse-dev -y

git submodule init
git submodule update

cd phc-winner-argon2
make
sudo make install PREFIX=/usr 
make test

cd ../pam_enc_dir
./setup_pam.sh

cd ../enc_dir_fuse
./setup_fuse.sh


if [[ -f /etc/pam.d/common-session ]] # delete old pam module
then 
  echo "session optional pam_enc_dir.so" >> /etc/pam.d/common-session
  echo "auth optional pam_enc_dir.so" >> /etc/pam.d/common-auth
fi
