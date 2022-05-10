#!/usr/bin/perl
$ENV{'PATH'} = '/bin:/usr/bin';
-d "xt" && "$^X xt/60_perlcritic.t" =~ /(.*)/ ||
           "$^X ../xt/60_perlcritic.t" =~ /(.*)/;
exec($1);
