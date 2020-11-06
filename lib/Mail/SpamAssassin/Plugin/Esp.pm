# <@LICENSE>
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to you under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# </@LICENSE>

# Author:  Giovanni Bechis <gbechis@apache.org>

=head1 NAME

Esp - checks ESP abused accounts

=head1 SYNOPSIS

  loadplugin    Mail::SpamAssassin::Plugin::Esp

=head1 DESCRIPTION

This plugin checks emails coming from ESP abused accounts.

=cut

package Mail::SpamAssassin::Plugin::Esp;

use strict;
use warnings;

use Errno qw(EBADF);
use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::PerMsgStatus;

use vars qw(@ISA);
our @ISA = qw(Mail::SpamAssassin::Plugin);

my $VERSION = 1.0;

sub dbg { Mail::SpamAssassin::Plugin::dbg ("Esp: @_"); }

sub new {
  my $class = shift;
  my $mailsaobject = shift;

  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->set_config($mailsaobject->{conf});
  $self->register_eval_rule('esp_sendgrid_check_domain',  $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule('esp_sendgrid_check_id',  $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule('esp_sendgrid_check',  $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule('esp_sendinblue_check',  $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule('esp_mailup_check',  $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);

  return $self;
}

=head1 SYNOPSIS

loadplugin Mail::SpamAssassin::Plugin::Esp Esp.pm

ifplugin Mail::SpamAssassin::Plugin::Esp

  sendgrid_feed /etc/mail/spamassassin/sendgrid-id-dnsbl.txt
  sendgrid_domains_feed /etc/mail/spamassassin/sendgrid-envelopefromdomain-dnsbl.txt

  header          SPBL_SENDGRID           eval:esp_sendgrid_check()
  describe        SPBL_SENDGRID           Message from Sendgrid abused account

endif

Usage:

  esp_mailup_check()
    Checks for Mailup abused accounts

  esp_sendindblue_check()
    Checks for Sendinblue abused accounts

  esp_sendgrid_check()
    Checks for Sendgrid abused accounts

  esp_sendgrid_check_id()
    Checks for Sendgrid id abused accounts

  esp_sendgrid_check_domain()
    Checks for Sendgrid domains abused accounts

=head1 ADMINISTRATOR SETTINGS

=over 4

=item sendgrid_feed [...]

A file with all abused Sendgrid accounts.
More info at https://www.invaluement.com/serviceproviderdnsbl/.
Data file can be downloaded from https://www.invaluement.com/spdata/sendgrid-id-dnsbl.txt.

=item sendgrid_domains_feed [...]

A file with abused domains managed by Sendgrid.
More info at https://www.invaluement.com/serviceproviderdnsbl/.
Data file can be downloaded from https://www.invaluement.com/spdata/sendgrid-envelopefromdomain-dnsbl.txt.

=item sendinblue_feed [...]

A file with abused Sendinblue accounts.

=item mailup_feed [...]

A file with abused Mailup accounts.

=back

=head1 TEMPLATE TAGS

=over

The plugin sets some tags when a rule match, those tags can be used to use direct queries against rbl.

If direct queries are used the main rule will be used only to set the tag and the score should be
added to the askdns rule.

  ifplugin Mail::SpamAssassin::Plugin::AskDNS
    askdns   SENDGRID_ID _SENDGRIDID_.rbl.domain.tld A 127.0.0.2
    describe SENDGRID_ID Sendgrid account matches rbl
  endif

Tags that the plugin could set are:

=back

=over

=item *
SENDGRIDID

=item *
SENDGRIDDOM

=item *
SENDINBLUEID

=item *
MAILUPID

=back

=cut

sub set_config {
  my($self, $conf) = @_;
  my @cmds = ();

  push(@cmds, {
    setting => 'sendgrid_feed',
    is_admin => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    }
  );
  push(@cmds, {
    setting => 'sendgrid_domains_feed',
    is_admin => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    }
  );
  push(@cmds, {
    setting => 'sendinblue_feed',
    is_admin => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    }
  );
  push(@cmds, {
    setting => 'mailup_feed',
    is_admin => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    }
  );
  $conf->{parser}->register_commands(\@cmds);
}

sub finish_parsing_end {
  my ($self, $opts) = @_;
  $self->_read_configfile($self);
}

sub _read_configfile {
  my ($self) = @_;
  my $conf = $self->{main}->{registryboundaries}->{conf};
  my $sendgrid_id;
  my $sendgrid_domain;
  my $sendinblue_id;
  my $mailup_id;

  local *F;
  if ( defined($conf->{sendgrid_feed}) && ( -f $conf->{sendgrid_feed} ) ) {
    open(F, '<', $conf->{sendgrid_feed});
    for ($!=0; <F>; $!=0) {
      chomp;
      #lines that start with pound are comments
      next if(/^\s*\#/);
      $sendgrid_id = $_;
      if ( defined $sendgrid_id ) {
        push @{$self->{ESP}->{SENDGRID}->{$sendgrid_id}}, $sendgrid_id;
      }
    }

    defined $_ || $!==0  or
      $!==EBADF ? dbg("ESP: error reading config file: $!")
                : die "error reading config file: $!";
    close(F) or die "error closing config file: $!";
  }

  if ( defined($conf->{sendgrid_domains_feed}) && ( -f $conf->{sendgrid_domains_feed} ) ) {
    open(F, '<', $conf->{sendgrid_domains_feed});
    for ($!=0; <F>; $!=0) {
      chomp;
      #lines that start with pound are comments
      next if(/^\s*\#/);
      $sendgrid_domain = $_;
      if ( defined $sendgrid_domain ) {
        push @{$self->{ESP}->{SENDGRID_DOMAIN}->{$sendgrid_domain}}, $sendgrid_domain;
      }
    }

    defined $_ || $!==0  or
      $!==EBADF ? dbg("ESP: error reading config file: $!")
                : die "error reading config file: $!";
    close(F) or die "error closing config file: $!";
  }

  if ( defined($conf->{sendinblue_feed}) && ( -f $conf->{sendinblue_feed} ) ) {
    open(F, '<', $conf->{sendinblue_feed});
    for ($!=0; <F>; $!=0) {
      chomp;
      #lines that start with pound are comments
      next if(/^\s*\#/);
      $sendinblue_id = $_;
      if ( ( defined $sendinblue_id ) and ($sendinblue_id =~ /[0-9]+/) ) {
        push @{$self->{ESP}->{SENDINBLUE}->{$sendinblue_id}}, $sendinblue_id;
      }
    }

    defined $_ || $!==0  or
      $!==EBADF ? dbg("ESP: error reading config file: $!")
                : die "error reading config file: $!";
    close(F) or die "error closing config file: $!";
  }

  if ( defined($conf->{mailup_feed}) && ( -f $conf->{mailup_feed} ) ) {
    open(F, '<', $conf->{mailup_feed});
    for ($!=0; <F>; $!=0) {
      chomp;
      #lines that start with pound are comments
      next if(/^\s*\#/);
      $mailup_id = $_;
      if ( defined $mailup_id ) {
        push @{$self->{ESP}->{MAILUP}->{$mailup_id}}, $mailup_id;
      }
    }

    defined $_ || $!==0  or
      $!==EBADF ? dbg("ESP: error reading config file: $!")
                : die "error reading config file: $!";
    close(F) or die "error closing config file: $!";
  }

}

sub esp_sendgrid_check_domain {
  my ($self, $pms) = @_;
  my $sendgrid_id;
  my $sendgrid_domain;

  # All Sendgrid emails have the X-SG-EID header
  my $sg_eid = $pms->get("X-SG-EID", undef);
  return if not defined $sg_eid;

  my $rulename = $pms->get_current_eval_rule_name();
  my $envfrom = $pms->get("EnvelopeFrom:addr", undef);
  return if not defined $envfrom;

  # Find the domain from the Return-Path
  if($envfrom =~ /\@(\w+\.)?([\w\.]+)\>?$/) {
    $sendgrid_domain = $2;
    # dbg("ENVFROM: $envfrom domain: $sendgrid_domain");
    if(defined $sendgrid_domain) {
      $pms->set_tag('SENDGRIDDOM', $sendgrid_domain);
      if ( exists $self->{ESP}->{SENDGRID_DOMAIN}->{$sendgrid_domain} ) {
        dbg("HIT! $sendgrid_domain domain found in Sendgrid Invaluement feed");
        $pms->test_log("Sendgrid domain: $sendgrid_domain");
        $pms->got_hit($rulename, "", ruletype => 'eval');
        return 1;
      }
    }
  }
}

sub esp_sendgrid_check_id {
  my ($self, $pms) = @_;
  my $sendgrid_id;
  my $sendgrid_domain;

  # All Sendgrid emails have the X-SG-EID header
  my $sg_eid = $pms->get("X-SG-EID", undef);
  return if not defined $sg_eid;

  my $rulename = $pms->get_current_eval_rule_name();
  my $envfrom = $pms->get("EnvelopeFrom:addr", undef);
  return if not defined $envfrom;

  # Find the customer id from the Return-Path
  if($envfrom =~ /bounces\+(\d+)\-/) {
    $sendgrid_id = $1;
    # dbg("ENVFROM: $envfrom ID: $sendgrid_id");
    if(defined $sendgrid_id) {
      $pms->set_tag('SENDGRIDID', $sendgrid_id);
      if ( exists $self->{ESP}->{SENDGRID}->{$sendgrid_id} ) {
        dbg("HIT! $sendgrid_id customer id found in Sendgrid Invaluement feed");
        $pms->test_log("Sendgrid id: $sendgrid_id");
        $pms->got_hit($rulename, "", ruletype => 'eval');
        return 1;
      }
    }
  }
}

sub esp_sendgrid_check {
  my ($self, $pms) = @_;

  my $ret;

  $ret = $self->esp_sendgrid_check_id($pms);
  if (!$ret) {
    $ret = $self->esp_sendgrid_check_domain($pms);
  }
  return $ret;
}

sub esp_sendinblue_check {
  my ($self, $pms) = @_;
  my $sendinblue_id;

  my $rulename = $pms->get_current_eval_rule_name();
  my $envfrom = $pms->get("EnvelopeFrom:addr", undef);
  # All Sendinblue emails have the X-Mailer header set to Sendinblue
  my $xmailer = $pms->get("X-Mailer", undef);
  if((not defined $xmailer) or ($xmailer !~ /Sendinblue/)) {
    return;
  }

  $sendinblue_id = $pms->get("X-Mailin-Client", undef);
  return if not defined $sendinblue_id;
  chomp($sendinblue_id);
  if(defined $sendinblue_id) {
    if ( exists $self->{ESP}->{SENDINBLUE}->{$sendinblue_id} ) {
      $pms->set_tag('SENDINBLUEID', $sendinblue_id);
      dbg("HIT! $sendinblue_id ID found in Sendinblue feed");
      $pms->test_log("Sendinblue id: $sendinblue_id");
      $pms->got_hit($rulename, "", ruletype => 'eval');
      return 1;
    }
  }

}

sub esp_mailup_check {
  my ($self, $pms) = @_;
  my $mailup_id;

  my $rulename = $pms->get_current_eval_rule_name();

  # All Mailup emails have the X-CSA-Complaints header set to whitelist-complaints@eco.de
  my $xcsa = $pms->get("X-CSA-Complaints", undef);
  if((not defined $xcsa) or ($xcsa !~ /whitelist-complaints\@eco\.de/)) {
    return;
  }
  # All Mailup emails have the X-Abuse header that must match
  $mailup_id = $pms->get("X-Abuse", undef);
  return if not defined $mailup_id;
  $mailup_id =~ /Please report abuse here: http\:\/\/.*\.musvc([0-9]+)\.net\/p\?c=([0-9]+)/;
  $mailup_id = $2;
  # if regexp doesn't match it's not Mailup
  return if not defined $mailup_id;
  chomp($mailup_id);
  if(defined $mailup_id) {
    if ( exists $self->{ESP}->{MAILUP}->{$mailup_id} ) {
      $pms->set_tag('MAILUPID', $mailup_id);
      dbg("HIT! $mailup_id customer found in Mailup feed");
      $pms->test_log("Mailup id: $mailup_id");
      $pms->got_hit($rulename, "", ruletype => 'eval');
      return 1;
    }
  }

}
1;
