#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("dmarc");

use Test::More;

use vars qw(%patterns %anti_patterns);

use constant HAS_MAILSPF => eval { require Mail::SPF; };
use constant HAS_DKIM_VERIFIER => eval {
  require Mail::DKIM::Verifier;
  version->parse(Mail::DKIM::Verifier->VERSION) >= version->parse(0.31);
};
use constant HAS_MAILDMARC => eval { require Mail::DMARC::PurePerl; };

plan skip_all => "Net tests disabled" unless conf_bool('run_net_tests');
plan skip_all => "Needs Mail::SPF" unless HAS_MAILSPF;
plan skip_all => "Needs Mail::DMARC::PurePerl" unless HAS_MAILDMARC;
plan skip_all => "Needs Mail::DKIM::Verifier >= 0.31" unless HAS_DKIM_VERIFIER ;
plan tests => 18;

tstprefs("

header SPF_PASS     eval:check_for_spf_pass()
tflags SPF_PASS     nice userconf net
full   DKIM_SIGNED  eval:check_dkim_signed()
tflags DKIM_SIGNED  net

# Check that rename backwards compatibility works with if's
ifplugin Mail::SpamAssassin::Plugin::Dmarc
if plugin ( Mail::SpamAssassin::Plugin::Dmarc)
ifplugin Mail::SpamAssassin::Plugin::DMARC

header DMARC_PASS eval:check_dmarc_pass()
tflags DMARC_PASS net

header DMARC_NONE eval:check_dmarc_none()
tflags DMARC_NONE net

header DMARC_QUAR eval:check_dmarc_quarantine()
tflags DMARC_QUAR net

header DMARC_REJECT eval:check_dmarc_reject()
tflags DMARC_REJECT net

header DMARC_MISSING eval:check_dmarc_missing()
tflags DMARC_MISSING net

endif
endif
endif
");

##
## PASS
##

%patterns = (
    q{ DMARC_PASS } => '',
);
%anti_patterns = (
    qr/DMARC_(?!PASS)/ => '',
);

sarun ("-t < data/nice/dmarc/noneok.eml", \&patterns_run_cb);
ok_all_patterns();

sarun ("-t < data/nice/dmarc/quarok.eml", \&patterns_run_cb);
ok_all_patterns();

sarun ("-t < data/nice/dmarc/rejectok.eml", \&patterns_run_cb);
ok_all_patterns();

sarun ("-t < data/nice/dmarc/strictrejectok.eml", \&patterns_run_cb);
ok_all_patterns();

##
## REJECT
##

%patterns = (
    q{ DMARC_REJECT } => '',
);
%anti_patterns = (
    qr/DMARC_(?!REJECT)/ => '',
);

sarun ("-t < data/spam/dmarc/rejectko.eml", \&patterns_run_cb);
ok_all_patterns();

sarun ("-t < data/spam/dmarc/strictrejectko.eml", \&patterns_run_cb);
ok_all_patterns();

##
## QUAR
##

%patterns = (
    q{ DMARC_QUAR } => '',
);
%anti_patterns = (
    qr/DMARC_(?!QUAR)/ => '',
);

sarun ("-t < data/spam/dmarc/quarko.eml", \&patterns_run_cb);
ok_all_patterns();

##
## NONE
##

%patterns = (
    q{ DMARC_NONE } => '',
);
%anti_patterns = (
    qr/DMARC_(?!NONE)/ => '',
);

sarun ("-t < data/spam/dmarc/noneko.eml", \&patterns_run_cb);
ok_all_patterns();

##
## MISSING
##

%patterns = (
    q{ DMARC_MISSING } => '',
);
%anti_patterns = (
    qr/DMARC_(?!MISSING)/ => '',
);

sarun ("-t < data/spam/dmarc/nodmarc.eml", \&patterns_run_cb);
ok_all_patterns();

