#!/bin/sh

cd /home/jm/ftp/spamassassin/masses

(
./kill_continual_evolve.sh
) > log2 2>&1

