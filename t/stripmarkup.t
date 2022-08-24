#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("stripmarkup");
use Test::More tests => 4;

# ---------------------------------------------------------------------------

%patterns = (
  qr/^Content-Type: text\/html$/m, 'contenttype',
  qr/\nSender: pertand\@email\.mondolink\.com\nContent-Type: text\/html\n\n<HTML><\/P>/, 'startofbody',
  qr/^Subject: "100% HERBALSENSATION"$/m, 'subj',
);

tstprefs ( "
  rewrite_header subject *****SPAM*****
" );

ok (sarun ("-d < data/spam/003", \&patterns_run_cb));
ok_all_patterns();

