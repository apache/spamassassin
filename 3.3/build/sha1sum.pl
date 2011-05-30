#!/usr/bin/perl

BEGIN {
  eval { require Digest::SHA; import Digest::SHA qw(sha1_hex); 1 }
  or do { require Digest::SHA1; import Digest::SHA1 qw(sha1_hex) }
}

$/=undef;

while(<>) {
  print sha1_hex($_),"  $ARGV\n";
}
