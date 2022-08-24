#!/usr/bin/perl -T

use lib '.'; use lib 't';
use SATest; sa_t_init("priorities");
use strict;
use Test::More tests => 10;

use Mail::SpamAssassin;

disable_compat "welcomelist_blocklist";

tstlocalrules (q{

  body BAYES_99		eval:check_bayes('0.99', '1.00')
  tflags BAYES_99		learn
  score BAYES_99 0 0 3.5 3.5

  header USER_IN_BLOCKLIST		eval:check_from_in_blocklist()
  describe USER_IN_BLOCKLIST		From: user is listed in the block-list
  tflags USER_IN_BLOCKLIST		userconf nice noautolearn
  score USER_IN_BLOCKLIST		100

  if !can(Mail::SpamAssassin::Conf::compat_welcomelist_blocklist)
    meta USER_IN_BLACKLIST		(USER_IN_BLOCKLIST)
    describe USER_IN_BLACKLIST		DEPRECATED: See USER_IN_BLOCKLIST
    tflags USER_IN_BLACKLIST		userconf nice noautolearn
    score USER_IN_BLACKLIST		100
    score USER_IN_BLOCKLIST		0.01
  endif

  header USER_IN_WELCOMELIST		eval:check_from_in_welcomelist()
  describe USER_IN_WELCOMELIST		User is listed in 'welcomelist_from'
  tflags USER_IN_WELCOMELIST		userconf nice noautolearn
  score USER_IN_WELCOMELIST		-100
    
  if !can(Mail::SpamAssassin::Conf::compat_welcomelist_blocklist)
    meta USER_IN_WHITELIST		(USER_IN_WELCOMELIST)
    describe USER_IN_WHITELIST		DEPRECATED: See USER_IN_WELCOMELIST
    tflags USER_IN_WHITELIST		userconf nice noautolearn
    score USER_IN_WHITELIST		-100
    score USER_IN_WELCOMELIST		-0.01
  endif

  header USER_IN_DEF_WELCOMELIST	eval:check_from_in_default_welcomelist()
  describe USER_IN_DEF_WELCOMELIST	From: user is listed in the default welcome-list
  tflags USER_IN_DEF_WELCOMELIST	userconf nice noautolearn
  score USER_IN_DEF_WELCOMELIST		-15
  
  if !can(Mail::SpamAssassin::Conf::compat_welcomelist_blocklist)
    meta USER_IN_DEF_WHITELIST		(USER_IN_DEF_WELCOMELIST)
    describe USER_IN_DEF_WHITELIST	DEPRECATED: See USER_IN_WELCOMELIST 
    tflags USER_IN_DEF_WHITELIST	userconf nice noautolearn
    score USER_IN_DEF_WHITELIST		-15
    score USER_IN_DEF_WELCOMELIST	-0.01
  endif

  header USER_IN_BLOCKLIST_TO		eval:check_to_in_blocklist()
  describe USER_IN_BLOCKLIST_TO       	User is listed in 'blocklist_to'
  tflags USER_IN_BLOCKLIST_TO		userconf nice noautolearn
  score USER_IN_BLOCKLIST_TO	     	10

  if !can(Mail::SpamAssassin::Conf::compat_welcomelist_blocklist)
    meta USER_IN_BLACKLIST_TO		(USER_IN_BLOCKLIST_TO)
    describe USER_IN_BLACKLIST_TO	DEPRECATED: See USER_IN_BLOCKLIST_TO
    tflags USER_IN_BLACKLIST_TO		userconf nice noautolearn
    score USER_IN_BLACKLIST_TO		10
    score USER_IN_BLOCKLIST_TO		0.01
  endif
  header USER_IN_WELCOMELIST_TO		eval:check_to_in_welcomelist()
  describe USER_IN_WELCOMELIST_TO	User is listed in 'welcomelist_to'
  tflags USER_IN_WELCOMELIST_TO		userconf nice noautolearn
  score USER_IN_WELCOMELIST_TO		-6

  if !can(Mail::SpamAssassin::Conf::compat_welcomelist_blocklist)
    meta USER_IN_WHITELIST_TO		(USER_IN_WELCOMELIST_TO)
    describe USER_IN_WHITELIST_TO	DEPRECATED: See USER_IN_WELCOMELIST_TO
    tflags USER_IN_WHITELIST_TO		userconf nice noautolearn
    score USER_IN_WHITELIST_TO		-6
    score USER_IN_WELCOMELIST_TO	-0.01
  endif

  header USER_IN_ALL_SPAM_TO      eval:check_to_in_all_spam()
  tflags USER_IN_ALL_SPAM_TO      userconf nice noautolearn

  priority USER_IN_WHITELIST     -1000
  priority USER_IN_DEF_WHITELIST -1000
  priority USER_IN_ALL_SPAM_TO   -1000
  priority SUBJECT_IN_WHITELIST  -1000

  priority ALL_TRUSTED            -950

  priority SUBJECT_IN_BLACKLIST   -900
  priority USER_IN_BLACKLIST_TO   -900
  priority USER_IN_BLACKLIST      -900

  priority BAYES_99               -400

  header XX_RCVD_IN_SORBS_SMTP     eval:check_rbl_sub('sorbs', '127.0.0.5')
  tflags XX_RCVD_IN_SORBS_SMTP     net
  score  XX_RCVD_IN_SORBS_SMTP     1

  meta SC_URIBL_SURBL  (URIBL_BLACK && (URIBL_SC_SURBL || URIBL_JP_SURBL || URIBL_OB_SURBL ) && RCVD_IN_SORBS_SMTP)
  meta SC_URIBL_HASH   ((URIBL_BLACK || URIBL_SC_SURBL || URIBL_JP_SURBL || URIBL_OB_SURBL) && (RAZOR2_CHECK || DCC_CHECK || PYZOR_CHECK))
  meta SC_URIBL_SBL    ((URIBL_BLACK || URIBL_SC_SURBL || URIBL_JP_SURBL || URIBL_OB_SURBL) && URIBL_SBL)
  meta SC_URIBL_BAYES  ((URIBL_BLACK || URIBL_SC_SURBL || URIBL_JP_SURBL || URIBL_OB_SURBL) && BAYES_99)

  shortcircuit SC_URIBL_SURBL        spam
  shortcircuit SC_URIBL_HASH         spam
  shortcircuit SC_URIBL_SBL          spam
  shortcircuit SC_URIBL_BAYES        spam

  priority SC_URIBL_SURBL            -530
  priority SC_URIBL_HASH             -510
  priority SC_URIBL_SBL              -510
  priority SC_URIBL_BAYES            -510

  shortcircuit DIGEST_MULTIPLE       spam
  priority DIGEST_MULTIPLE           -300

  meta FOO1 (FOO2 && FOO3)
  meta FOO2 (1)
  meta FOO3 (FOO4 && FOO5)
  meta FOO4 (2)
  meta FOO5 (3)
  priority FOO5 -23
  priority FOO1 -28

});

my $sa = create_saobj({
  dont_copy_prefs => 1,
  # debug => 1
});

$sa->init(0); # parse rules
ok($sa);
my $conf = $sa->{conf};
sub assert_rule_pri;

ok assert_rule_pri 'USER_IN_WHITELIST', -1000;

ok assert_rule_pri 'SC_URIBL_SURBL', -530;
ok assert_rule_pri 'SC_URIBL_HASH', -510;
ok assert_rule_pri 'SC_URIBL_SBL', -510;
ok assert_rule_pri 'SC_URIBL_BAYES', -510;
ok assert_rule_pri 'XX_RCVD_IN_SORBS_SMTP', -530;

# SC_URIBL_BAYES will have overridden its base priority setting
ok assert_rule_pri 'BAYES_99', -510;

ok assert_rule_pri 'FOO5', -28;
ok assert_rule_pri 'FOO1', -28;

# ---------------------------------------------------------------------------

sub assert_rule_pri {
  my ($r, $pri) = @_;

  if (defined $conf->{rbl_evals}->{$r} || defined $conf->{meta_tests}->{$r}) {
    # ignore rbl_evals and metas; they do not use the priority system at all
    return 1;
  }

  foreach my $ruletype (qw(
    body_tests head_tests meta_tests uri_tests rawbody_tests full_tests
    full_evals rawbody_evals head_evals body_evals
  ))
  {
    if (defined $conf->{$ruletype}->{$pri}->{$r}) {
      return 1;
    }
    foreach my $foundpri (keys %{$conf->{priorities}}) {
      next unless (defined $conf->{$ruletype}->{$foundpri}->{$r});
      warn "FAIL: rule '$r' not found at priority $pri; found at $foundpri\n";
      return 0;
    }
  }

  warn "FAIL: no rule '$r' found of any type at any priority\n";
  return 0;
}

