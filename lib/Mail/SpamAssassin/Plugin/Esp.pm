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

my $VERSION = 1.6.0;

sub dbg { my $msg = shift; Mail::SpamAssassin::Plugin::dbg("Esp: $msg", @_); }

sub new {
  my $class = shift;
  my $mailsaobject = shift;

  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->set_config($mailsaobject->{conf});
  $self->register_eval_rule('esp_constantcontact_check',  $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule('esp_maildome_check',  $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule('esp_mailchimp_check',  $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule('esp_mailgun_check',  $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule('esp_mailup_check',  $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule('esp_mdrctr_check',  $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule('esp_sendgrid_check_domain',  $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule('esp_sendgrid_check_id',  $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule('esp_sendgrid_check',  $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule('esp_sendinblue_check',  $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);

  return $self;
}

=head1 SYNOPSIS

loadplugin Mail::SpamAssassin::Plugin::Esp Esp.pm

ifplugin Mail::SpamAssassin::Plugin::Esp

  sendgrid_feed /etc/mail/spamassassin/sendgrid-id-dnsbl.txt,/etc/mail/spamassassin/sendgrid-id-local.txt
  sendgrid_domains_feed /etc/mail/spamassassin/sendgrid-envelopefromdomain-dnsbl.txt

  header          SPBL_SENDGRID           eval:esp_sendgrid_check()
  describe        SPBL_SENDGRID           Message from Sendgrid abused account

endif

Usage:

  esp_constantcontact_check()
    Checks for Constant Contact id abused accounts

  esp_mailchimp_check()
    Checks for Mailchimp abused accounts

  esp_maildome_check()
    Checks for Maildome abused accounts

  esp_mailgun_check()
    Checks for Mailgun abused accounts

  esp_mailup_check()
    Checks for Mailup abused accounts

  esp_mdrctr_check()
    Checks for Mdirector id abused accounts

  esp_sendgrid_check()
    Checks for Sendgrid abused accounts (both id and domains)

  esp_sendgrid_check_id()
    Checks for Sendgrid id abused accounts

  esp_sendgrid_check_domain()
    Checks for Sendgrid domains abused accounts

  esp_sendindblue_check()
    Checks for Sendinblue abused accounts

=head1 ADMINISTRATOR SETTINGS

=over 4

=item constantcontact_feed [...]

A list of files with abused Constant Contact accounts.
Files can be separated by a comma.

=item mailchimp_feed [...]

A list of files with abused Mailchimp accounts.
Files can be separated by a comma.

=item maildome_feed [...]

A list of files with abused Maildome accounts.
Files can be separated by a comma.

=item mailgun_feed [...]

A list of files with abused Mailgun accounts.
Files can be separated by a comma.

=item mailup_feed [...]

A list of files with abused Mailup accounts.
Files can be separated by a comma.

=item mdrctr_feed [...]

A list of files with abused Mdirector accounts.
Files can be separated by a comma.

=item sendgrid_domains_feed [...]

A list of files with abused domains managed by Sendgrid.
Files can be separated by a comma.

=item sendgrid_feed [...]

A list of files with all abused Sendgrid accounts.
Files can be separated by a comma.

=item sendinblue_feed [...]

A list of files with abused Sendinblue accounts.
Files can be separated by a comma.

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
CONSTANTCONTACTID

=item *
MAILCHIMPID

=item *
MAILDOMEID

=item *
MAILGUNID

=item *
MAILUPID

=item *
MDRCTRID

=item *
SENDGRIDDOM

=item *
SENDGRIDID

=item *
SENDINBLUEID

=back

=cut

sub set_config {
  my($self, $conf) = @_;
  my @cmds = ();

  push(@cmds, {
    setting => 'constantcontact_feed',
    is_admin => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    }
  );
  push(@cmds, {
    setting => 'mailchimp_feed',
    is_admin => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    }
  );
  push(@cmds, {
    setting => 'maildome_feed',
    is_admin => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    }
  );
  push(@cmds, {
    setting => 'mailgun_feed',
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
  push(@cmds, {
    setting => 'mdrctr_feed',
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
    setting => 'sendgrid_feed',
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
  $conf->{parser}->register_commands(\@cmds);
}

sub finish_parsing_end {
  my ($self, $opts) = @_;
  $self->_read_configfile('constantcontact_feed', 'CONSTANTCONTACT');
  $self->_read_configfile('mailchimp_feed', 'MAILCHIMP');
  $self->_read_configfile('maildome_feed', 'MAILDOME');
  $self->_read_configfile('mailgun_feed', 'MAILGUN');
  $self->_read_configfile('mailup_feed', 'MAILUP');
  $self->_read_configfile('mdrctr_feed', 'MDRCTR');
  $self->_read_configfile('sendgrid_domains_feed', 'SENDGRID_DOMAINS');
  $self->_read_configfile('sendgrid_feed', 'SENDGRID');
  $self->_read_configfile('sendinblue_feed', 'SENDINBLUE');
}

sub _read_configfile {
  my ($self, $feed, $esp) = @_;
  my $conf = $self->{main}->{registryboundaries}->{conf};
  my $id;

  local *F;

  return if not defined $conf->{$feed};

  my @feed_files = split(/,/, $conf->{$feed});
  foreach my $feed_file ( @feed_files ) {
    if ( defined($feed_file) && ( -f $feed_file ) ) {
      open(F, '<', $feed_file);
      for ($!=0; <F>; $!=0) {
        chomp;
        #lines that start with pound are comments
        next if(/^\s*\#/);
        $id = $_;
        if ( defined $id ) {
          push @{$self->{ESP}->{$esp}->{$id}}, $id;
        }
      }

      defined $_ || $!==0  or
        $!==EBADF ? dbg("ESP: error reading config file: $!")
                  : die "error reading config file: $!";
      close(F) or die "error closing config file: $!";
    }
  }
}

sub _hit_and_tag {
  my ($self, $pms, $id, $list, $list_desc, $tag) = @_;

  my $rulename = $pms->get_current_eval_rule_name();
  chomp($id);
  if(defined $id) {
    $pms->set_tag($tag, $id);
    if ( exists $self->{ESP}->{$list}->{$id} ) {
      dbg("HIT! $id customer found in $list_desc feed");
      $pms->test_log("$list_desc id: $id");
      $pms->got_hit($rulename, "", ruletype => 'eval');
      return 1;
    }
  }
}

sub esp_constantcontact_check {
  my ($self, $pms) = @_;
  my $contact_id;

  # return if X-Mailer is not what we want
  my $xmailer = $pms->get("X-Mailer", undef);

  if((not defined $xmailer) or ($xmailer !~ /Roving\sConstant\sContact/)) {
    return;
  }

  my $envfrom = $pms->get("EnvelopeFrom:addr", undef);
  return if not defined $envfrom;
  return if $envfrom !~ /\@in\.constantcontact\.com/;

  $contact_id = $pms->get("X-Roving-Id", undef);
  return if not defined $contact_id;
  return if ($contact_id !~ /^(\d+)\.\d+$/);

  return _hit_and_tag($self, $pms, $contact_id, 'CONSTANTCONTACT', 'Constant Contact', 'CONSTANTCONTACTID');
}

sub esp_mailchimp_check {
  my ($self, $pms) = @_;
  my $mailchimp_id;

  # return if X-Mailer is not what we want
  my $xmailer = $pms->get("X-Mailer", undef);

  if((not defined $xmailer) or ($xmailer !~ /MailChimp Mailer/i)) {
    return;
  }

  $mailchimp_id = $pms->get("X-MC-User", undef);
  return if not defined $mailchimp_id;
  return if ($mailchimp_id !~ /^([0-9a-z]{25})$/);

  return _hit_and_tag($self, $pms, $mailchimp_id, 'MAILCHIMP', 'Mailchimp', 'MAILCHIMPID');
}

sub esp_maildome_check {
  my ($self, $pms) = @_;
  my $maildome_id;

  # return if X-Mailer is not what we want
  my $xmailer = $pms->get("X-Mailer", undef);

  if((not defined $xmailer) or ($xmailer !~ /MaildomeMTA/)) {
    return;
  }

  $maildome_id = $pms->get("List-Unsubscribe", undef);
  return if not defined $maildome_id;
  $maildome_id =~ /subject=https:\/\/.*\/unsubscribe\/([0-9]+)\/([0-9]+)\/.*\/([0-9]+)\/([0-9]+)\>/;
  $maildome_id = $2;

  # if regexp doesn't match it's not Maildome
  return if not defined $maildome_id;
  return _hit_and_tag($self, $pms, $maildome_id, 'MAILDOME', 'Maildome', 'MAILDOMEID');
}

sub esp_mailgun_check {
  my ($self, $pms) = @_;
  my $mailgun_id;

  # Mailgun doesn't define an X-Mailer header
  my $xmailer = $pms->get("X-Mailer", undef);
  if(defined $xmailer) {
    return;
  }

  my $xsendip = $pms->get("X-Mailgun-Sending-Ip", undef);
  if(not defined $xsendip) {
    return;
  }

  my $envfrom = $pms->get("EnvelopeFrom:addr", undef);
  return if not defined $envfrom;
  # Find the customer id from the Return-Path
  $envfrom =~ /bounce\+(\w+)\.(\w+)\-/;
  $mailgun_id = $2;

  return _hit_and_tag($self, $pms, $mailgun_id, 'MAILGUN', 'Mailgun', 'MAILGUNID');
}

sub esp_mailup_check {
  my ($self, $pms) = @_;
  my ($mailup_id, $xabuse, $listid);

  # All Mailup emails have the X-CSA-Complaints header set to *-complaints@eco.de
  my $xcsa = $pms->get("X-CSA-Complaints", undef);
  if((not defined $xcsa) or ($xcsa !~ /\-complaints\@eco\.de/)) {
    return;
  }
  # All Mailup emails have the X-Abuse header that must match
  $xabuse = $pms->get("X-Abuse", undef);
  return if not defined $xabuse;
  if($xabuse =~ /Please report abuse here: https?:\/\/.*\.musvc([0-9]+)\.net\/p\?c=([0-9]+)/) {
    $mailup_id = $2;
  }
  if(not defined $mailup_id) {
    $listid = $pms->get("list-id", undef);
    if($listid =~ /\<(\d+)\.\d+\>/) {
      $mailup_id = $1;
    }
  }
  # if regexp doesn't match it's not Mailup
  return if not defined $mailup_id;

  return _hit_and_tag($self, $pms, $mailup_id, 'MAILUP', 'Mailup', 'MAILUPID');
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
    return _hit_and_tag($self, $pms, $sendgrid_domain, 'SENDGRID_DOMAIN', 'Sendgrid', 'SENDGRIDDOM');
  }
}

sub esp_sendgrid_check_id {
  my ($self, $pms) = @_;
  my $sendgrid_id;
  my $sendgrid_domain;

  # All Sendgrid emails have the X-SG-EID header
  my $sg_eid = $pms->get("X-SG-EID", undef);
  return if not defined $sg_eid;

  my $envfrom = $pms->get("EnvelopeFrom:addr", undef);
  return if not defined $envfrom;

  # Find the customer id from the Return-Path
  if($envfrom =~ /bounces\+(\d+)\-/) {
    $sendgrid_id = $1;
    # dbg("ENVFROM: $envfrom ID: $sendgrid_id");
    return _hit_and_tag($self, $pms, $sendgrid_id, 'SENDGRID', 'Sendgrid', 'SENDGRIDID');
  }
}

sub esp_sendinblue_check {
  my ($self, $pms) = @_;
  my $sendinblue_id;

  my $feedback_id = $pms->get("Feedback-ID", undef);
  return if not defined $feedback_id;

  if($feedback_id =~ /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:(\d+)_(?:-1|\d+):(?:\d+):Sendinblue$/) {
    $sendinblue_id = $1;
  }

  return if not defined $sendinblue_id;

  return _hit_and_tag($self, $pms, $sendinblue_id, 'SENDINBLUE', 'Sendinblue', 'SENDINBLUEID');
}

sub esp_mdrctr_check {
  my ($self, $pms) = @_;
  my $mdrctr_id;

  # All Mdrctr emails have the X-ElasticEmail-Postback header
  my $sg_eid = $pms->get("X-ElasticEmail-Postback", undef);
  return if not defined $sg_eid;

  my $fid = $pms->get("Feedback-ID", undef);
  return if not defined $fid;

  my $envfrom = $pms->get("EnvelopeFrom:addr", undef);
  return if ($envfrom !~ /bounces\.mdrctr\.com/);

  # Find the customer id from the Feedback-ID
  if($fid =~ /(\d+):(\d+):([a-z]+)/i) {
    $mdrctr_id = $1;
    return _hit_and_tag($self, $pms, $mdrctr_id, 'MDRCTR', 'Mdrctr', 'MDRCTRID');
  }
}

1;
