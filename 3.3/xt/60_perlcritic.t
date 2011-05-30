#!/usr/bin/perl

use strict;
use warnings;
use File::Spec;
use Test::More;
use English qw(-no_match_vars);

BEGIN {
  if (-d 'xt') { chdir 'xt'; }

  if (-e 'test_dir') {            # running from test directory, not ..
    unshift(@INC, '../blib/lib');
    unshift(@INC, '../lib');
  }
}

eval { require Test::Perl::Critic; };

if ( $EVAL_ERROR ) {
    my $msg = 'Test::Perl::Critic required to criticise code';
    plan( skip_all => $msg );
}

open RC, ">../t/log/perlcritic.rc" or die "cannot write t/log/perlcritic.rc";

# we should remove some of these excludes if/when we feel like fixing 'em!
print RC q{

  severity = 5
  verbose = 10
  exclude = ValuesAndExpressions::ProhibitLeadingZeros InputOutput::ProhibitBarewordFileHandles InputOutput::ProhibitTwoArgOpen TestingAndDebugging::RequireUseStrict Subroutines::ProhibitExplicitReturnUndef Variables::RequireLexicalLoopIterators Subroutines::ProhibitSubroutinePrototypes BuiltinFunctions::ProhibitStringyEval InputOutput::ProhibitInteractiveTest

  [TestingAndDebugging::ProhibitNoStrict]
  allow = refs

};
close RC;

Test::Perl::Critic->import( -profile => "../t/log/perlcritic.rc" );
all_critic_ok("../blib");

