#!/bin/bash
wget jamesbyron.net/proxy_grade.py
wget jamesbyron.net/valid.sh
wget jamesbyron.net/diff_test.sh
wget jamesbyron.net/neg_test.sh
wget jamesbyron.net/sites-head
wget jamesbyron.net/sites-tail
chmod +x *.sh
touch block
mkdir dout
python3 proxy_grade.py lastFirst_12345_1234567_submisssion $1
rm dout/* block
killall myproxy
killall curl
