#!/usr/bin/perl

use lib '.'; use lib 't';
use SATest; sa_t_init("recips");
use Test; BEGIN { plan tests => 6 };

# ---------------------------------------------------------------------------

%patterns = ( q{ SORTED_RECIPS } => 'SORTED_RECIPS',
	      q{ SUSPICIOUS_RECIPS } => 'SUSPICIOUS_RECIPS');
%anti_patterns = ( );

sarun ("-L -t < data/spam/010", \&patterns_run_cb);
ok_all_patterns();

%patterns = ( q{ SUSPICIOUS_RECIPS } => 'SUSPICIOUS_RECIPS');
%anti_patterns = ( q{ SORTED_RECIPS } => 'SORTED_RECIPS');

sarun ("-L -t < data/spam/011", \&patterns_run_cb);
ok_all_patterns();

%patterns = ( );
%anti_patterns = ( q{ SORTED_RECIPS } => 'SORTED_RECIPS',
		   q{ SUSPICIOUS_RECIPS } => 'SUSPICIOUS_RECIPS');

sarun ("-L -t < data/nice/006", \&patterns_run_cb);
ok_all_patterns();
