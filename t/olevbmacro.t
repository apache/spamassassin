#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("olevbmacro");

use constant HAS_ARCHIVE_ZIP => eval { require Archive::Zip; };
use constant HAS_IO_STRING => eval { require IO::String; };

use Test::More;
plan skip_all => 'Need Archive::Zip for this test' unless HAS_ARCHIVE_ZIP;
plan skip_all => 'Need IO::String for this test' unless HAS_IO_STRING;
plan tests => 12;

tstlocalrules (q{
  loadplugin Mail::SpamAssassin::Plugin::OLEVBMacro

  olemacro_extended_scan 1

  body     OLEMACRO_FOUND eval:check_olemacro()
  score    OLEMACRO_FOUND 0.1
  body     OLEMACRO_MALICE eval:check_olemacro_malice()
  score    OLEMACRO_MALICE 0.1
  body     OLEMACRO_RENAME eval:check_olemacro_renamed()
  score    OLEMACRO_RENAME 0.1
  body     OLEMACRO_ENCRYPTED eval:check_olemacro_encrypted()
  score    OLEMACRO_ENCRYPTED 0.1
  body     OLEMACRO_ZIP_PW eval:check_olemacro_zip_password()
  score    OLEMACRO_ZIP_PW 0.1
  body     OLEMACRO_CSV eval:check_olemacro_csv()
  score    OLEMACRO_CSV 0.1
  body     OLEMACRO_TURI eval:check_olemacro_redirect_uri()
  score    OLEMACRO_TURI 0.1
});


%patterns = (
  q{ 0.1 OLEMACRO_FOUND }, 'OLEMACRO_FOUND',
);

sarun ("-L -t < data/spam/olevbmacro/macro.eml", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

%patterns = (
  q{ 0.1 OLEMACRO_FOUND }, 'OLEMACRO_FOUND',
  q{ 0.1 OLEMACRO_MALICE }, 'OLEMACRO_MALICE',
);

sarun ("-L -t < data/spam/olevbmacro/malicemacro.eml", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

%patterns = (
  q{ 0.1 OLEMACRO_FOUND }, 'OLEMACRO_FOUND',
  q{ 0.1 OLEMACRO_RENAME }, 'OLEMACRO_RENAME',
);

sarun ("-L -t < data/spam/olevbmacro/renamedmacro.eml", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

%patterns = (
  q{ 0.1 OLEMACRO_ENCRYPTED }, 'OLEMACRO_ENCRYPTED',
);

sarun ("-L -t < data/spam/olevbmacro/encrypted.eml", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

%patterns = (
  q{ 0.1 OLEMACRO_FOUND }, 'OLEMACRO_FOUND',
  q{ 0.1 OLEMACRO_ZIP_PW }, 'OLEMACRO_ZIP_PW',
);

sarun ("-L -t < data/spam/olevbmacro/zippwmacro.eml", \&patterns_run_cb);
ok_all_patterns();
clear_pattern_counters();

%patterns = ();
%anti_patterns = (
  q{ 0.1 OLEMACRO_FOUND }, 'OLEMACRO_FOUND',
);

sarun ("-L -t < data/spam/olevbmacro/nomacro.eml", \&patterns_run_cb);
ok_all_patterns();

%patterns = ();
%anti_patterns = (
  q{ 0.1 OLEMACRO_FOUND }, 'OLEMACRO_FOUND',
  q{ 0.1 OLEMACRO_CSV }, 'OLEMACRO_CSV',
);

sarun ("-L -t < data/spam/olevbmacro/goodcsv.eml", \&patterns_run_cb);
ok_all_patterns();

%patterns = (
  q{ 0.1 OLEMACRO_TURI }, 'OLEMACRO_TURI',
);
%anti_patterns = ();

sarun ("-L -t < data/spam/olevbmacro/target_uri.eml", \&patterns_run_cb);
ok_all_patterns();
