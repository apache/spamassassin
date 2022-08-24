#!/usr/bin/perl -T
# Wrapper around test until perlcritic fixes bug running under -T

# sa_t_init handles a number of necessary cross-platform initialization that is necessary
# even though this wrapper doesn't need most things that are also in there
use lib '.'; use lib 't';
use SATest; sa_t_init('perlcritic');

use strict;
use warnings;

-d "t" && "$^X t/perlcritic.pl" =~ /(.*)/ ||
    "$^X perlcritic.pl" =~ /(.*)/;
exec($1);
