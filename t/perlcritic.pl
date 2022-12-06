#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init('perlcritic');

use strict;
use warnings;
use Test::More;
use English qw(-no_match_vars);

plan skip_all => "This test requires Test::Perl::Critic" unless (eval { require Test::Perl::Critic; 1} );
plan skip_all => "PerlCritic test cannot run in Taint mode" if (${^TAINT});

open RC, ">../t/log/perlcritic.rc"  or die "cannot create t/log/perlcritic.rc";

# we should remove some of these excludes if/when we feel like fixing 'em!
print RC q{

  severity = 5
  verbose = 9
  exclude = ValuesAndExpressions::ProhibitLeadingZeros InputOutput::ProhibitBarewordDirHandles InputOutput::ProhibitBarewordFileHandles InputOutput::ProhibitTwoArgOpen BuiltinFunctions::ProhibitStringyEval InputOutput::ProhibitInteractiveTest Bangs::ProhibitBitwiseOperators Bangs::ProhibitDebuggingModules Compatibility::ProhibitThreeArgumentOpen Lax::ProhibitStringyEval::ExceptForRequire Lax::ProhibitLeadingZeros::ExceptChmod ValuesAndExpressions::PreventSQLInjection ControlStructures::ProhibitReturnInDoBlock ValuesAndExpressions::ProhibitAccessOfPrivateData Policy::OTRS::

  [TestingAndDebugging::ProhibitNoStrict]
  allow = refs

  [Perlsecret]
  allow_secrets = Venus

}  or die "cannot write t/log/perlcritic.rc";
close RC  or die "cannot close t/log/perlcritic.rc";

Test::Perl::Critic->import( -profile => "../t/log/perlcritic.rc" );
all_critic_ok("../blib");

