#!/bin/sh

pid=`cat cont_evolve.pid`
kill $pid
killall evolve
kill $pid
rm -f cont_evolve.pid
