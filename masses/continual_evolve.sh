#!/bin/sh

count=1
while true ; do
  ./evolve 
  mv results.evolved result.$count 
  echo "Copied to results.$count"
  count=`expr $count + 1`
done

