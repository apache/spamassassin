#!/usr/local/bin/perl
use Digest::MD5 qw/md5_hex/;
print md5_hex(<STDIN>),"\n";
