#!/usr/bin/perl -T
# Wrapper around test until perlcritic fixes bug running under -T
$ENV{'PATH'} = '/bin:/usr/bin';
-d "t" && "$^X t/perlcritic.pl" =~ /(.*)/ ||
    "$^X perlcritic.pl" =~ /(.*)/;
exec($1);
