#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("authres");

use Test::More;
plan tests => 44;

# ---------------------------------------------------------------------------

tstpre ("
loadplugin Mail::SpamAssassin::Plugin::AuthRes
");

## with internal networks

tstprefs("
  clear_internal_networks
  clear_trusted_networks
  internal_networks 212.17.35.15
  trusted_networks 212.17.35.15
  trusted_networks 141.154.95.22
");

%patterns = (
        'parsing Authentication-Results: authrestest1int', 'hdr1',
        'parsing Authentication-Results: authrestest2int', 'hdr2',
        'parsing Authentication-Results: authrestest3int', 'hdr3',
        'parsing Authentication-Results: authrestest4int', 'hdr4',
        'parsing Authentication-Results: authrestest5int', 'hdr5',
        'parsing Authentication-Results: authrestest6int', 'hdr6',
        'authres: results: dkim=pass dmarc=none spf=pass', 'results',
            );

%anti_patterns = (
        'parsing Authentication-Results: authrestest7tru', 'hdr7',
        'parsing Authentication-Results: authrestest8ext', 'hdr8',
        'authres: no Authentication-Results headers found', 'nohdr',
        'authres: skipping header,', 'skipping',
            );

sarun ("-D authres -L -t < data/nice/authres 2>&1", \&patterns_run_cb);
ok_all_patterns();


## with trusted networks included

tstprefs("
  clear_internal_networks
  clear_trusted_networks
  internal_networks 212.17.35.15
  trusted_networks 212.17.35.15
  trusted_networks 141.154.95.22

  authres_networks trusted
");

%patterns = (
        'parsing Authentication-Results: authrestest1int', 'hdr1',
        'parsing Authentication-Results: authrestest2int', 'hdr2',
        'parsing Authentication-Results: authrestest3int', 'hdr3',
        'parsing Authentication-Results: authrestest4int', 'hdr4',
        'parsing Authentication-Results: authrestest5int', 'hdr5',
        'parsing Authentication-Results: authrestest6int', 'hdr6',
        'parsing Authentication-Results: authrestest7tru', 'hdr7',
        'authres: results: dkim=pass dmarc=none spf=pass', 'results',
            );

%anti_patterns = (
        'parsing Authentication-Results: authrestest8ext', 'hdr8',
        'authres: no Authentication-Results headers found', 'nohdr',
        'authres: skipping header,', 'skipping',
            );

sarun ("-D authres -L -t < data/nice/authres 2>&1", \&patterns_run_cb);
ok_all_patterns();


## with all networks (test ignore also)

tstprefs("
  clear_internal_networks
  clear_trusted_networks
  internal_networks 212.17.35.15
  trusted_networks 212.17.35.15
  trusted_networks 141.154.95.22

  authres_networks all
  authres_ignored_authserv authrestest3int authrestest4int
");

%patterns = (
        'parsing Authentication-Results: authrestest1int', 'hdr1',
        'parsing Authentication-Results: authrestest2int', 'hdr2',
        'parsing Authentication-Results: authrestest3int', 'hdr3',
        'parsing Authentication-Results: authrestest4int', 'hdr4',
        'parsing Authentication-Results: authrestest5int', 'hdr5',
        'parsing Authentication-Results: authrestest6int', 'hdr6',
        'parsing Authentication-Results: authrestest7tru', 'hdr7',
        'parsing Authentication-Results: authrestest8ext', 'hdr8',
        'authres: results: dkim=pass dmarc=none spf=pass', 'results',
        'authres: skipping header, ignored authserv: authrestest3int', 'skip3',
        'authres: skipping header, ignored authserv: authrestest4int', 'skip4',
            );

%anti_patterns = (
        'authres: no Authentication-Results headers found', 'nohdr',
            );

sarun ("-D authres -L -t < data/nice/authres 2>&1", \&patterns_run_cb);
ok_all_patterns();

## with all networks (test trusted also)

tstprefs("
  clear_internal_networks
  clear_trusted_networks
  internal_networks 212.17.35.15
  trusted_networks 212.17.35.15
  trusted_networks 141.154.95.22

  authres_networks all
  authres_trusted_authserv authrestest6int
");

%patterns = (
        'dbg: authres: skipping header, authserv not trusted: authrestest1int', 'skip1',
        'dbg: authres: skipping header, authserv not trusted: authrestest2int', 'skip2',
        'dbg: authres: skipping header, authserv not trusted: authrestest3int', 'skip3',
        'dbg: authres: skipping header, authserv not trusted: authrestest4int', 'skip4',
        'dbg: authres: skipping header, authserv not trusted: authrestest5int', 'skip5',
        'dbg: authres: skipping header, authserv not trusted: authrestest7tru', 'skip6',
        'dbg: authres: skipping header, authserv not trusted: authrestest8ext', 'skip7',
        'parsing Authentication-Results: authrestest6int', 'parsing',
        'authres: results: dkim=fail', 'results',
            );

%anti_patterns = (
        'authres: no Authentication-Results headers found', 'nohdr',
            );

sarun ("-D authres -L -t < data/nice/authres 2>&1", \&patterns_run_cb);
ok_all_patterns();

