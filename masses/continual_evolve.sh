#!/bin/sh

count=1
echo $$ > cont_evolve.pid

while [ -f result.$count ] ; do
  count=`expr $count + 1`
done

echo "restarting evolve at result.$count"

while true ; do
  ./evolve $*
  mv results.evolved result.$count 
  echo "Copied to result.$count"
  count=`expr $count + 1`
done

rm -f cont_evolve.pid
