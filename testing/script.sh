#!/bin/bash

gcc fusetest.c ../utils/enc_utils.c -o fusetest `pkg-config fuse --cflags --libs` -lsodium
echo "./fusetest -f /home/foda-se/gitlab/transparent_enc_ba/testing/testmount1"