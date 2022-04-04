#!/usr/bin/perl

# <@LICENSE>
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to you under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# </@LICENSE>

#
# Usage: lm_to_languages.pl <indir> <languages>
#
# Packs directory of .lm files into SA "languages" file
#

die "Invalid languages" unless $ARGV[1];
die "Invalid indir" unless -d $ARGV[0];

load_models($ARGV[0]);

sub load_models {
  my ($indir) = @_;

  opendir(IN, $indir) or die;
  my @files = grep { /\.lm$/ } readdir(IN);
  closedir(IN) or die;
  die unless @files;

  open(LANGUAGES, ">$ARGV[1]") or die;
  binmode LANGUAGES or die;

  foreach my $f (sort @files) {
    my $outl = $f;
    $outl =~ s/\.lm$//;
    $outl =~ s!.*/!!;
    open(IN, "$indir/$f") or die;
    binmode IN or die;
    my $cnt = 0;
    while (<IN>) {
      s/\r?\n$//;
      /^([^0-9\s]+)/ or die;
      print LANGUAGES "$1\n" or die;
      $cnt++;
    }
    close IN or die;
    print LANGUAGES "0 $outl\n" or die;
    print STDERR "Read $outl ($cnt)\n";
  }

  close LANGUAGES or die;
  print STDERR "Wrote $ARGV[1]\n";
}

