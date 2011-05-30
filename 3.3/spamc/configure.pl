#!/usr/bin/perl
# autoconf wrapper (for Unix)/alternative (for Windows)
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


use strict;
use warnings;
use Config;

use File::Copy;
use File::Spec::Functions qw(:ALL);

use Cwd qw(chdir);

use constant RUNNING_ON_NATIVE_WINDOWS => ($^O =~ /^(mswin|dos|os2)/i);


# Some nicer error messages.
$SIG{__DIE__} = sub {
  die join(': ', $0, @_);
};


# Build our argument list to call the real configure script later.
our @args = (q{./configure});
our %args;
foreach (@ARGV) {
  if (/^--([^=]+?)=["']?(.*?)["']?$/) {
    $args{$1} = $2;
    push(@args, $_);
  }
  elsif (/^([^=]+?)=["']?(.*?)["']?$/) {
    $ENV{$1} = $2;
  }
}


# Change to the dir this file is in.
my $srcdir;
$srcdir = canonpath(catpath((splitpath($0))[0..1])) || curdir();
if ($srcdir ne curdir()) {
  print "cd $srcdir\n";
  chdir($srcdir) || die "Can't cd to `$srcdir': $!";
}


# Create version.h platform independently.
print join(' ', $Config{'perlpath'}, "version.h.pl") . "\n";
{
  # Do the same thing as for the preprocessor below.
  package version_h;
  my $Z = $0;
  local $0    = "version.h.pl";
  local @ARGV = ();
  # Got to check for defined because the script returns shell error level!
  unless (defined do $0) {
    $0 = $Z;
    die $@ ? $@ : "Can't exec `version.h.pl': $!";
  }
}


# On everything but native Windows (!= cygwin) we use autoconf.
unless (RUNNING_ON_NATIVE_WINDOWS)
{
  print join(' ', @args) . "\n";
  exec @args;
  exit 127;
}
# For Windows we've got our own little autoconf :)
else
{
  # These are the defaults for the Makefile.
  my %env = (
    CC             => 'cl',

    WINCFLAGS      => '/DWIN32 /W4',
    SSLCFLAGS      => '/DSPAMC_SSL',

    SRCDIR         =>  $srcdir,

    WINLIBS        => 'ws2_32.lib',
    SSLLIBS        => 'ssleay32.lib libeay32.lib',

    SPAMC_FILES    => 'spamc.c getopt.c',
    LIBSPAMC_FILES => 'libspamc.c utils.c',
  );

  # Enable SSL only if requested.
  if ($args{'enable-ssl'} and $args{'enable-ssl'} ne 'yes') {
    delete $env{SSLCFLAGS};
    delete $env{SSLLIBS};
  }
  # Set every unset var in env to it's default value so the preprocessor
  # gets it later on.
  foreach (keys %env) {
    $ENV{$_} = $env{$_} unless $ENV{$_};
  }

  # Now do the real work...
  print "copy config.h.win config.h\n";
  copy(q{config.h.win}, q{config.h}) || die "Can't copy `config.h.win' to `config.h': $!";
  print "copy spamc.h.win spamc.h\n";
  copy(q{spamc.h.win}, q{spamc.h}) || die "Can't copy `spamc.h.win' to `spamc.h': $!";

  # We'll use our preprocessor for variable replacement in the Makefile.
  # Note that variables are enclosed by *two* @s while autoconf uses only
  # one.
  @args = (
    catfile(updir(), 'build', 'preprocessor'),
    q{-Mvars},
    q{-iMakefile.win},
    q{-oMakefile}
  );
  print join(' ', $Config{'perlpath'}, @args) . "\n";
  {
    # We now call the preprocessor in its own namespace (so it doesn't
    # clobber the main namespace. Feed its ARGV and do some zeroth-argument
    # tricks to get nicer error messages.
    package preprocessor;
    my $Z = $0;
    $0    = $::args[0];
    @ARGV = @::args[1 .. 3];
    # Got to check for defined because the script returns shell error level!
    unless (defined do $0) {
      $0 = $Z;
      die $@ ? $@ : "Can't exec `$::args[0]': $!";
    }
  }

  if ($srcdir ne curdir()) {
    print "cd " . updir() . "\n" for splitdir($srcdir);
  }
} #* RUNNING_ON_NATIVE_WINDOWS *#
