# MemoryDump - save summaries of memory usage to files.
#
# Normally not "use"d by any code, purely for manual debugging.
# To use, pepper code with this:
#
# use Mail::SpamAssassin::Util::MemoryDump; Mail::SpamAssassin::Util::MemoryDump::MEMDEBUG();
#
# or:
#
# use Mail::SpamAssassin::Util::MemoryDump; Mail::SpamAssassin::Util::MemoryDump::MEMDEBUG_dump_obj();
#
# and run script with MEMDEBUG=1 set in the environment;
# "MEMDEBUG=1 spamassassin -Lt", for example.
#
# Each MEMDEBUG() statement will produce a file in a 'dumps' subdirectory.
#
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

package Mail::SpamAssassin::Util::MemoryDump;

use strict;
use warnings;
use bytes;
use re 'taint';

BEGIN {
  use Exporter ();
  our @ISA = qw(Exporter);
  our @EXPORT_OK = qw(MEMDEBUG MEMDEBUG_dump_obj);
}
our $COUNTER = 0;

use Devel::Peek qw();
use Devel::Size qw(size total_size);
use Mail::SpamAssassin::Util qw(proc_status_ok exit_status_str);
eval q{ use Devel::Gladiator; };

###########################################################################

sub MEMDEBUG {
  return unless $ENV{'MEMDEBUG'};
  census_arena();
}

sub MEMDEBUG_dump_obj {
  return unless $ENV{'MEMDEBUG'};
  dump_obj(@_);
}

###########################################################################

sub census_arena {
  # lots of good stuff nicked from bradfitz@SixApart's djabberd

  warn "MEMDEBUG: census arena start\n";

  my $name = new_dump_filename("census");

  # do this in a subprocess, since it leaks refs to all objects!
  my $pid = fork();
  if ($pid) {
    my $child_stat = waitpid($pid,0) > 0 ? $? : undef;
    proc_status_ok($child_stat)
      or warn "census subproc: ".exit_status_str($child_stat);
    return;
  }

  # we are now in a subprocess
  open (DUMP, ">$name") or warn "cannot write to $name";

  my ($x, $y, $c, $subroutine, $d) = caller(2);
  my ($e, $filename, $line, $f) = caller(1);
  print DUMP "${subroutine}()\n";
  print DUMP "$filename line: $line\n";

  print DUMP "\nMEMDEBUG: census_arena:
(some values may be 0 due to bugs in Devel::Size etc.; this tends to be buggy)
";

  my %objcount;
  my %size;
  eval {
    my $all = Devel::Gladiator::walk_arena();
    %objcount = ();
    %size = ();

    # be selective and don't use Devel::Size on GLOBs and some other ref
    # types, it coredumps on several of them (perl 5.8.8, linux)

    my $s;
    foreach my $val (@$all) {
      if (ref $val eq 'REF') {
        $objcount{ref ${$val}}++;
        $size{ref $val} += get_obj_size($val);
      }
      elsif (ref $val eq 'CODE') {
        eval {
          $objcount{Devel::Peek::CvGV($val)}++;
          # $size{ref $val} += Devel::Size::size($val);
        };
      }
      elsif (ref $val eq 'Regexp') {
        $size{ref $val} += get_obj_size($val);
      }
      elsif (ref $val eq 'HASH') {
        $size{ref $val} += get_obj_size($val);
      }
      elsif (ref $val eq 'ARRAY') {
        $size{ref $val} += get_obj_size($val);
      }
      elsif (ref $val eq 'SCALAR') {
        $size{ref $val} += get_obj_size($val);
      }

      $objcount{ref $val}++;
    }
    1;
  } or do {
    my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
    warn "census: $eval_stat\n";
  };

  foreach my $id (sort { $objcount{$b} <=> $objcount{$a} } keys %objcount) {
    my $c = $objcount{$id};
    my $s = $size{$id} || 0;
    next unless ($c > 10 || $s > 1024*256);
    print DUMP "$c $s $id\n";
  }

  my $ps = `ps lxww`; $ps =~ /^(.*? $$ .*)$/m;
  print DUMP "\n$1\n";

  close DUMP or warn "close failed";
  warn "MEMDEBUG: census arena end: wrote to $name\n";
  exit;         # fork over!
}

sub get_obj_size {
  my $s = Devel::Size::size($_[0]);
  # argh -- ignore buggy items
  if ($s < 0 || $s > 10000000) { return 0; }
  return $s;
}

###########################################################################

sub dump_obj {
  my $obj = shift;
  warn "MEMDEBUG_dump_obj start\n";

  my $name = new_dump_filename("obj");

  open (DUMP, ">$name") or warn "cannot write to $name";

  my ($x, $y, $c, $subroutine, $d) = caller(2);
  my ($e, $filename, $line, $f) = caller(1);
  print DUMP "${subroutine}()\n";
  print DUMP "$filename line: $line\n";

  print DUMP "MEMDEBUG_dump_obj:\n";

  eval {
    use Data::Dumper;
    $Data::Dumper::Purity = 0;
    $Data::Dumper::Terse = 1;
    my $dump = Dumper($obj);
    $dump =~ s/ {8}/  /gs;
    print DUMP $dump;
    1;
  } or do {
    my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
    warn "dump: $eval_stat\n";
  };

  close DUMP or warn "close failed";
  warn "MEMDEBUG_dump_obj end: wrote to $name\n";
}

###########################################################################

sub new_dump_filename {
  my $type = shift;
  if (!-d "dumps") {
    mkdir("dumps", 0777)  or warn "dump: cannot create a directory: $!";
  }

  my ($e, $filename, $line, $f) = caller(2);
  $filename =~ s/^.*[\/\\]//gs;
  $filename =~ s/[^A-Za-z0-9\.]/_/gs;

  $COUNTER++;
  my $str = sprintf("dumps/%06d.%06d.%s_%d.%s", $$, $COUNTER,
            $filename, $line, $type);
  return $str;
}

1;
