#!/usr/bin/perl -w

# This script is really sketchy and probably should be re-written to
# be less sketchy.

# These numbers for lengths are correct AFAIK for 2.60. You'll need to
# change them manually if they change.

# read descriptions into the hash descriptions
# find max length and save it into length

use strict;

my (%description, %length, %file);
my $len;

while (<>) {

  if (/^describe\s+(\S+)\s+(.*)$/) {
    $description{$1} = $2;
    $file{$1} = $ARGV;
    next;
  }

  if (/^header\s+(\S+)\s+rbleval:/) {
    $length{$1} = 45;
    next;
  }
  if (/^header\s+(\S+)\s+/) {
    $length{$1} = 50;
    next;
  }
  if (/^body\s+(\S+)\s+/) {
    $length{$1} = 44;
    next;
  }
  if (/^uri\s+(\S+)\s+/) {
    $length{$1} = 45;
    next;
  }
  if (/^rawbody\s+(\S+)\s+eval/) {
     $length{$1} = 45;
     next;
  }
  if (/^rawbody\s+(\S+)\s+/) {
     $length{$1} = 44;
     next;
  }
  if (/^full\s+(\S+)\s+eval:/) {
     $length{$1} = 50;
     next;
  }
  if (/^full\s+(\S+)\s+/) {
     $length{$1} = 44;
     next;
  }
  if (/^meta\s+(\S+)\s+/) {
     $length{$1} = 50;
     next;
  }
}

print "The following tests have names that are too long:\n";
print "-" x 22 . "\n";
foreach my $test (sort keys %length) {
  next if ($test =~ /^[T_]_/);
  print "$test\n" if length($test) > 22;
}

print "\nThe following tests have descriptions but are not defined:\n";
foreach my $test (sort keys %description) {
  next if $length{$test};
  print "$test\n";
  delete $description{$test};
}

# find descs that are too long
print "\nThe following tests have no description:\n";
foreach my $test (sort keys %length) {
  if (($test !~ /^[T_]_/) && !$description{$test}) {
    print "$test\n";
  }
  delete $length{$test} if !$description{$test};
  delete $file{$test} if !$description{$test};
}

print "\nThe following tests have descriptions that are too long:\n";
foreach my $test (sort {$file{$a} cmp $file{$b} || $a cmp $b} (keys %file)) {
  $len = length($description{$test});
  if ($len > $length{$test}) {
      print "$test: max $length{$test}, cur $len ($file{$test})\n";
      print "  $description{$test}\n";
  }
}


