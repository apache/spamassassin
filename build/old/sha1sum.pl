#!/usr/bin/perl

BEGIN {
  eval { require Digest::SHA; Digest::SHA->import(qw(sha1_hex)); 1 }
  or do { require Digest::SHA1; Digest::SHA1->import(qw(sha1_hex)) }
}

$/=undef;

while(<>) {
  print sha1_hex($_),"  $ARGV\n";
}
