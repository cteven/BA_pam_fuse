#!/bin/bash

gcc testfuse.c ../utils/enc_utils.c -o testfuse `pkg-config fuse --cflags --libs` -lsodium
cp ./testfuse /usr/bin
# ./testfuse -f /home/foda-se/gitlab/transparent_enc_ba/user_fuse/test2