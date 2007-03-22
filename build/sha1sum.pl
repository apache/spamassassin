#!/usr/bin/perl
use Digest::SHA1 qw/sha1_hex/;

$/=undef;

while(<>) {
  print sha1_hex($_),"  $ARGV\n";
}
