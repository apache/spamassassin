#!/usr/bin/perl
use Digest::MD5 qw/md5_hex/;

$/=undef;

while(<>) {
  print md5_hex($_),"  $ARGV\n";
}
