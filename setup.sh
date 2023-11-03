#!/bin/bash

# gcc -fPIC -DPIC -shared -pthread -rdynamic -o pam_test.so ../phc-winner-argon2/libargon2.a pam_test.c
# gcc -L/home/steven/github/phc-winner-argon2 -Wall -fPIC -DPIC -shared -pthread -rdynamic -o pam_test.so pam_test.c -largon2
gcc -L/home/steven/github/phc-winner-argon2 -Wall -fPIC -DPIC -shared -pthread -rdynamic -o pam_test.so pam_test.c ../phc-winner-argon2/libargon2.so.1
rm /lib/x86_64-linux-gnu/security/pam_test.so
cp pam_test.so /lib/x86_64-linux-gnu/security/pam_test.so
chown root:root /lib/x86_64-linux-gnu/security/pam_test.so
chmod 755 /lib/x86_64-linux-gnu/security/pam_test.so

# PAM_MODULES_DIR=$(find /usr -name pam_test.so -print)

# echo $PAM_MODULES_DIR

# gcc -fPIC -DPIC -shared -pthread -rdynamic -o pam_test.so ../phc-winner-argon2/libargon2.a pam_test.c
# rm $PAM_MODULES_DIR
# cp pam_test.so $PAM_MODULES_DIR
# chown root:root $PAM_MODULES_DIR
# chmod 755 $PAM_MODULES_DIR


# find /lib -name pam_test.so -print
# locate -b '\pam_unix.so'