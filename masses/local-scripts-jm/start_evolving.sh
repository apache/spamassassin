#!/bin/sh

cd /home/jm/ftp/spamassassin/masses
(
make clean
make evolve && ./continual_evolve.sh -s 30000 -b 20.0 -c 1.001
)  > log 2>&1


# crontab: start at 1am, stop at 9am
# 3 1 * * *    /home/jm/ftp/spamassassin/masses/start_evolving.sh
# 3 9 * * *    /home/jm/ftp/spamassassin/masses/stop_evolving.sh

