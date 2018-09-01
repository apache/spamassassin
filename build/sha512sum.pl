#!/usr/bin/perl

BEGIN {
  require Digest::SHA; import Digest::SHA qw(sha256_hex sha512_hex);
}

$/=undef;

while(<>) {
  print sha512_hex($_),"  $ARGV\n";
}
