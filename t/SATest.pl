#!/usr/bin/perl
# Copyright (c) 2004 Malte S. Stretz

my %opts;
my @args;
{
  my $opts = 1;
  foreach (@ARGV) {
    if ($opts) {
      $opts     =  0 if /^--$/;
      $opts{$1} = $2 if /^-([a-zA-Z])(.+)$/;
    } else {
      push (@args, $_);
    }
  }
}

if ($opts{'M'} eq 'redirect') {
  my $stdout = $opts{'o'}   || die "No -o";
  my $stderr = $opts{'O'}   || die "No -O";
  open (STDOUT, ">$stdout") || die "Could not redirect STDOUT to $stdout: $!";
  open (STDERR, ">$stderr") || die "Could not redirect STDERR to $stderr: $!";
  
  $| = 1;
  exec { $args[0] } @args;
  die "Could not exec " . join(' ', @args) . ": $!";
}
else {
  die "Unknown mode: $mode\n";
}