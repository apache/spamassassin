#!/usr/local/bin/perl
use Digest::SHA1 qw/sha1_hex/;
print sha1_hex(<STDIN>),"\n";
