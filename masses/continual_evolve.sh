#!/bin/sh

count=1
echo $$ > cont_evolve.pid

while true ; do
  ./evolve $*
  mv results.evolved result.$count 
  echo "Copied to results.$count"
  count=`expr $count + 1`
done

rm -f cont_evolve.pid
