#!/bin/bash

# gcc -fPIC -DPIC -shared -pthread -rdynamic -o pam_enc_dir.so ../phc-winner-argon2/libargon2.a pam_enc_dir.c
# gcc -L/home/steven/github/phc-winner-argon2 -Wall -fPIC -DPIC -shared -pthread -rdynamic -o pam_enc_dir.so pam_enc_dir.c -largon2
# gcc -L/phc-winner-argon2 -Wall -fPIC -DPIC -shared -pthread -rdynamic -o pam_enc_dir.so pam_enc_dir.c phc-winner-argon2/libargon2.so.1
# rm /lib/x86_64-linux-gnu/security/pam_enc_dir.so
# cp pam_enc_dir.so /lib/x86_64-linux-gnu/security/pam_enc_dir.so
# chown root:root /lib/x86_64-linux-gnu/security/pam_enc_dir.so
# chmod 755 /lib/x86_64-linux-gnu/security/pam_enc_dir.so

PAM_MODULES_DIR=$(dirname $(find /usr -name pam_unix.so))

echo $PAM_MODULES_DIR/pam_enc_dir.so

gcc -L/phc-winner-argon2 -Wall -fPIC -DPIC -shared -pthread -rdynamic -o pam_enc_dir.so pam_enc_dir.c ./utils/enc_utils.c phc-winner-argon2/libargon2.so.1 -lsodium

if [[ -f $PAM_MODULES_DIR/pam_enc_dir.so ]] # maybe useless
then 
  rm $PAM_MODULES_DIR/pam_enc_dir.so 
fi

cp pam_enc_dir.so $PAM_MODULES_DIR
chown root:root $PAM_MODULES_DIR/pam_enc_dir.so
chmod 644 $PAM_MODULES_DIR/pam_enc_dir.so

cd enc_dir_fuse
./script.sh
