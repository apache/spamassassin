#!/usr/bin/perl
# This script isn't supposed to be run by hand, it's used by `make` as a pre-
# processor. It currently accepts two kinds of options on the command line:
#   -M<module>            Enables <module>
#   -D<variable>=<value>  Defines the <variable> to be <value>
#
# Those modules are currently implemented:
#   conditional          Comments out every line containing the string
#                        REMOVEFORINST
#   vars                 Replaces variables. Are upper case strings surrounded
#                        by double at-signs, eg. @@VERSION@@. The values are
#                        taken from the environment and can be overwritten with
#                        the -D switch. Empty/undefined variables are removed.
#   sharpbang            Does some sharpbang (#!) replacement. See code below.
#

use Config;


my %modules = ();
my %defines = ();

foreach (keys %ENV) {
  $defines{$_} = $ENV{$_};
}

foreach (@ARGV) {
  if    (/^-M([a-z]+)$/)       { $modules{$1} = 1; }
  elsif (/^-D([A-Z_]+)=(.*)$/) { $defines{$1} = $2; }
}


my $l = 1;
foreach (<STDIN>) {
  # Conditional compiling
  if ($modules{'conditional'}) {
    # Comment out lines carrying the REMOVEFORINST tag
    if(/\bREMOVEFORINST\b/) {
      s/^(\s*)/$1#/;
      s/REMOVEFORINST/REMOVEDBYINST/;
    }
  }

  # Variable replacement
  if ($modules{'vars'}) {
    # Replace all @@VARS@@
    s/\@\@([A-Z][A-Z0-9_]*)\@\@/$defines{$1}/g;
  }

  # Sharpbang (#!) replacement (see also ExtUtils::MY->fixin)
  if ($modules{'sharpbang'} && ($l == 1)) {
    # The perlpath can be overwritten via -DPERL_BIN=<perlpath>
    my $perl   = $defines{'PERL_BIN'} || $Config{'perlpath'};

    # If we're using a CVS build, add the -w switch to turn on warnings
    my $minusw = -f 'CVS/Repository' ? ' -w' : '';

    # The warnings can be overwritten via -DPERL_WARN=<1|0>
    if (defined $defines{'PERL_WARN'}) {
      $minusw = $defines{'PERL_WARN'} ? ' -w' : '';
    }
    s/^#!.*perl.*$/#!${perl}${minusw}/;
  }

  print;
  $l++;
}
