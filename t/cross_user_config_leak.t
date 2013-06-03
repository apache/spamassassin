#!/usr/bin/perl

BEGIN {
  if (-e 't/test_dir') { # if we are running "t/rule_tests.t", kluge around ...
    chdir 't';
  }

  if (-e 'test_dir') {            # running from test directory, not ..
    unshift(@INC, '../blib/lib');
    unshift(@INC, '../lib');
  }
}

my $prefix = '.';
if (-e 'test_dir') {            # running from test directory, not ..
  $prefix = '..';
}

use lib '.'; use lib 't';
use SATest; sa_t_init("cross_user_config_leak");
use Test; BEGIN { plan tests => 6 };

# ---------------------------------------------------------------------------
# bug 6003

# TODO: we could also do this by having a boolean attribute on the command
# structure itself to indicate that this test is superfluous.  But that's
# exposing a test-only feature through production code, so right now in my opinion
# this is cleaner.
#
my @ignored_commands = qw(

  score header body uri rawbody full meta test loadplugin tryplugin
  version_tag uri_detail uridnssub uridnsbl urirhsbl urirhssub urinsrhsbl
  urinsrhssub urifullnsrhsbl urifullnsrhssub add_header remove_header
  redirector_pattern reuse mimeheader rbl_timeout uridnsbl_timeout
  util_rb_tld util_rb_2tld util_rb_3tld shortcircuit asn_lookup

);

use strict;
use warnings;
require Mail::SpamAssassin;

my $sa = create_saobj({
    require_rules        => 1,
    local_tests_only     => 1,
    dont_copy_prefs      => 1,
    #debug=>1,
});

$sa->compile_now(0,1);
ok($sa);

print "Copying config to backup\n";
my %conf_backup;
$sa->copy_config(undef, \%conf_backup) or die "copy_config failed";
ok(scalar keys %conf_backup > 2);

# ---------------------------------------------------------------------------

# these need to be pretty improbable so they won't crop up in the defaults
my $EXPECTED_VAL_STRING         = '__test_expected_str';
my $EXPECTED_VAL_BOOL           = 1;
my $EXPECTED_VAL_BOOL_FALSE     = 0;
my $EXPECTED_VAL_NUMERIC        = 9438234;
my $EXPECTED_VAL_TEMPLATE       = '__test_expected_tmpl';
my $EXPECTED_VAL_HK_KEY         = '__test_expected_hk_key';
my $EXPECTED_VAL_HK_VALUE       = '__test_expected_hk_val';
my $EXPECTED_VAL_ADDRLIST       = '__test_expected_foo@bar.com';
my $EXPECTED_VAL_NOARGS         = '__test_expected_noargs';
my $EXPECTED_VAL_STRINGLIST     = [qw(__test_expected_s1 __test_expected_s2)];
my $EXPECTED_VAL_IPADDRLIST     = '__test_expected_';
my $EXPECTED_VAL_DURATION       = 9438234;

my %expected_val;
my %ignored_command;
foreach my $k (@ignored_commands) { $ignored_command{$k}++; }

print "Reading log/user_prefs1\n";
$sa->read_scoreonly_config("log/user_prefs1");
set_all_confs($sa->{conf});

$sa->signal_user_changed( { username => "user1", user_dir => "log/user1" });
ok validate_all_confs($sa->{conf}, 1, 'after first user config read');

print "Restoring config from backup\n";
$sa->copy_config(\%conf_backup, undef) or die "copy_config failed";
ok validate_all_confs($sa->{conf}, 0, 'after restoring from backup');


print "Reading log/user_prefs2\n";
$sa->read_scoreonly_config("log/user_prefs2");
$sa->signal_user_changed( { username => "user2", user_dir => "log/user2" });
ok validate_all_confs($sa->{conf}, 0, 'after second user config read');

print "Restoring config from backup, second time\n";
$sa->copy_config(\%conf_backup, undef) or die "copy_config failed";
ok validate_all_confs($sa->{conf}, 0, 'after second restore from backup');
exit;

# ---------------------------------------------------------------------------

sub set_all_confs {
  my ($conf) = @_;
  foreach my $cmd (@{$conf->{registered_commands}}) {
    my $k = $cmd->{setting};

    if (!defined $cmd->{type}) {
      next if $ignored_command{$k};
      next if ($cmd->{command} && $ignored_command{$cmd->{command}});

      # administrative commands by definition cannot change between users
      next if ($cmd->{is_admin});

      # attempt to infer types from the default value; if it's a scalar,
      # we can consider the type to be similarly scalar
      my $def = $cmd->{default};
      if (defined $def && ref $def =~ /SCALAR/) {
        if ("".$def =~ /[^\.\-\d]/) {
          $cmd->{type} = $Mail::SpamAssassin::Conf::CONF_TYPE_STRING;
        } else {
          $cmd->{type} = $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC;
          # we don't actually have to differentiate booleans and numeric,
          # they're stored the same anyway
        }
      }

      # ignore commands defined using custom code; we don't know how/what they
      # store.  Off for now; there's a lot of risk that we'll miss a bug if we
      # don't pay attention to them anyway. They can be dealt with on a
      # case-by-case basis using @ignored_commands instead.
      #
      ##next if defined $cmd->{code};
    }

    if (!defined $cmd->{type}) {
      warn "undef config type for $k".
                ($cmd->{command} ? " (command=$cmd->{command})" : "");
      next;
    }

    if ($cmd->{type} == $Mail::SpamAssassin::Conf::CONF_TYPE_NOARGS) {
      $conf->{$k} = $EXPECTED_VAL_NOARGS;
    }
    elsif ($cmd->{type} == $Mail::SpamAssassin::Conf::CONF_TYPE_STRING) {
      $conf->{$k} = $EXPECTED_VAL_STRING;
    }
    elsif ($cmd->{type} == $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL) {
      if ($cmd->{default} != $EXPECTED_VAL_BOOL) {
        $conf->{$k} = $EXPECTED_VAL_BOOL;
      } else {
        # we can't use the same value as the default, otherwise we'll
        # be unable to tell cases where the config has been leaked
        # from cases where the default is in use
        $conf->{$k} = $EXPECTED_VAL_BOOL_FALSE;
      }
    }
    elsif ($cmd->{type} == $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC) {
      $conf->{$k} = $EXPECTED_VAL_NUMERIC;
    }
    elsif ($cmd->{type} == $Mail::SpamAssassin::Conf::CONF_TYPE_DURATION) {
      $conf->{$k} = $EXPECTED_VAL_NUMERIC;
    }
    elsif ($cmd->{type} == $Mail::SpamAssassin::Conf::CONF_TYPE_TEMPLATE) {
      $conf->{$k} = $EXPECTED_VAL_TEMPLATE;
    }
    elsif ($cmd->{type} == $Mail::SpamAssassin::Conf::CONF_TYPE_STRINGLIST) {
      $conf->{$k} = [@$EXPECTED_VAL_STRINGLIST];
    }
    elsif ($cmd->{type} == $Mail::SpamAssassin::Conf::CONF_TYPE_IPADDRLIST) {
      $conf->{$k} = $EXPECTED_VAL_IPADDRLIST;
    }
    elsif ($cmd->{type} == $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE) {
      $conf->{$k}->{$EXPECTED_VAL_HK_KEY} = $EXPECTED_VAL_HK_VALUE;
    }
    elsif ($cmd->{type} == $Mail::SpamAssassin::Conf::CONF_TYPE_ADDRLIST) {
      $conf->add_to_addrlist($k, $EXPECTED_VAL_ADDRLIST);
    }

    if (ref $conf->{$k} eq 'ARRAY') {
      @{$expected_val{$k}} = @{$conf->{$k}};    # ensure this copies!
    } elsif (ref $conf->{$k} eq 'HASH') {
      %{$expected_val{$k}} = %{$conf->{$k}};
    } else {
      $expected_val{$k} = $conf->{$k};
    }
  }
}

my $setting_details;
my $validation_passed;
my $settings_should_exist;

sub validate_all_confs {
  my ($conf, $exist, $stage) = @_;

  $setting_details = '';
  $validation_passed = 1;
  $settings_should_exist = $exist;

  foreach my $cmd (@{$conf->{registered_commands}}) {
    my $k = $cmd->{setting};

    # if the default value is undef, it's a permitted value, obvs
    next if ($settings_should_exist && !defined $cmd->{default});

    $setting_details = "key='$k' when=$stage";
    if (!defined $cmd->{type}) {
      # warn "undef config type for $k";                # already done this
    }
    elsif ($cmd->{type} == $Mail::SpamAssassin::Conf::CONF_TYPE_NOARGS) {
      assert_validation($conf->{$k}, $expected_val{$k});
    }
    elsif ($cmd->{type} == $Mail::SpamAssassin::Conf::CONF_TYPE_STRING) {
      assert_validation($conf->{$k}, $expected_val{$k});
    }
    elsif ($cmd->{type} == $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL) {
      assert_validation($conf->{$k}, $expected_val{$k});
    }
    elsif ($cmd->{type} == $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC) {
      assert_validation($conf->{$k}, $expected_val{$k});
    }
    elsif ($cmd->{type} == $Mail::SpamAssassin::Conf::CONF_TYPE_DURATION) {
      assert_validation($conf->{$k}, $expected_val{$k});
    }
    elsif ($cmd->{type} == $Mail::SpamAssassin::Conf::CONF_TYPE_TEMPLATE) {
      assert_validation($conf->{$k}, $expected_val{$k});
    }
    elsif ($cmd->{type} == $Mail::SpamAssassin::Conf::CONF_TYPE_STRINGLIST) {
      # flatten for comparison
      my $val = $conf->{$k} ? join(" ", @{$conf->{$k}}) : undef;
      my $exp_val = $expected_val{$k} ? join(" ", @{$expected_val{$k}}) : undef;
      assert_validation($val, $exp_val);
    }
    elsif ($cmd->{type} == $Mail::SpamAssassin::Conf::CONF_TYPE_IPADDRLIST) {
      assert_validation($conf->{$k}, $expected_val{$k});
    }
    elsif ($cmd->{type} == $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE) {
      my $val = $conf->{$k}->{$EXPECTED_VAL_HK_KEY};
      assert_validation($val, $EXPECTED_VAL_HK_VALUE);
    }
    elsif ($cmd->{type} == $Mail::SpamAssassin::Conf::CONF_TYPE_ADDRLIST) {
      my $val = $conf->{$k}->{$EXPECTED_VAL_ADDRLIST};
      if (($settings_should_exist && !defined $val)
                || (!$settings_should_exist && $val))
      {
        assert_validation($k, $val, 0); # this will fail, which is what we want
      }
    } else {
      warn "unknown config type: $cmd->{type} for $k";
    }
  }
  return $validation_passed;
}

sub assert_validation {
  my ($val, $expected_val) = @_;
  if ($settings_should_exist && (!defined $val || $val ne $expected_val)) {
    warn "found=".(defined $val ? "'$val'" : "(none)").
        " wanted=".(defined $expected_val ? "'$expected_val'" : "(none)").
        " $setting_details";
    $validation_passed = 0;
  }
  if (!$settings_should_exist && defined($val) && "".$val eq "".$expected_val) {
    warn "found=".(defined $val ? "'$val'" : "(none)")." wanted=(none)".
        " $setting_details";
    $validation_passed = 0;
  }
}
