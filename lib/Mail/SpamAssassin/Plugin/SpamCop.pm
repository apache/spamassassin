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

=head1 NAME

Mail::SpamAssassin::Plugin::SpamCop - perform SpamCop reporting of messages

=head1 SYNOPSIS

  loadplugin     Mail::SpamAssassin::Plugin::SpamCop

=head1 DESCRIPTION

SpamCop is a service for reporting spam.  SpamCop determines the origin
of unwanted email and reports it to the relevant Internet service
providers.  By reporting spam, you have a positive impact on the
problem.  Reporting unsolicited email also helps feed spam filtering
systems, including, but not limited to, the SpamCop blocklist used in
SpamAssassin as a DNSBL.

Note that spam reports sent by this plugin to SpamCop each include the
entire spam message.

See https://www.spamcop.net/ for more information about SpamCop.

=cut

package Mail::SpamAssassin::Plugin::SpamCop;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Util qw(untaint_var);
use strict;
use warnings;
# use bytes;
use re 'taint';

use constant HAS_NET_SMTP => eval { require Net::SMTP; };

our @ISA = qw(Mail::SpamAssassin::Plugin);

sub new {
  my $class = shift;
  my $mailsaobject = shift;

  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  # are network tests enabled?
  if (!$mailsaobject->{local_tests_only} && HAS_NET_SMTP) {
    $self->{spamcop_available} = 1;
    dbg("reporter: network tests on, attempting SpamCop");
  }
  else {
    $self->{spamcop_available} = 0;
    dbg("reporter: local tests only, disabling SpamCop");
  }

  $self->set_config($mailsaobject->{conf});

  return $self;
}

sub set_config {
  my($self, $conf) = @_;
  my @cmds;

=head1 USER SETTINGS

=over 4

=item spamcop_from_address user@example.com   (default: none)

This address is used during manual reports to SpamCop as the From:
address.  You can use your normal email address.  If this is not set, a
guess will be used as the From: address in SpamCop reports.

=cut

  push (@cmds, {
    setting => 'spamcop_from_address',
    default => '',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value =~ /([^<\s]+\@[^>\s]+)/) {
	$self->{spamcop_from_address} = $1;
      }
      elsif ($value =~ /^$/) {
	return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      else {
	return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
    },
  });

=item spamcop_to_address user@example.com   (default: generic reporting address)

Your customized SpamCop report submission address.  You need to obtain
this address by registering at C<https://www.spamcop.net/>.  If this is
not set, SpamCop reports will go to a generic reporting address for
SpamAssassin users and your reports will probably have less weight in
the SpamCop system.

=cut

  push (@cmds, {
    setting => 'spamcop_to_address',
    default => 'spamassassin-submit@spam.spamcop.net',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value =~ /([^<\s]+\@[^>\s]+)/) {
	$self->{spamcop_to_address} = $1;
      }
      elsif ($value =~ /^$/) {
	return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      else {
	return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
    },
  });

=item spamcop_max_report_size   (default: 50)

Messages larger than this size (in kilobytes) will be truncated in
report messages sent to SpamCop.  The default setting is the maximum
size that SpamCop will accept at the time of release.

=cut

  push (@cmds, {
    setting => 'spamcop_max_report_size',
    default => 50,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });

=item spamcop_relayhost server:port  (default: direct connection to SpamCop)

Direct connection to SpamCop servers (port 587) is used for report
submission by default.  If this is undesirable or blocked by local firewall
policies, you can specify a local SMTP relayhost to forward reports. 
Relayhost should be configured to not scan the report, for example by using
a separate submission port.  SSL or authentication is not supported.

=cut

  push (@cmds, {
    setting => 'spamcop_relayhost',
    default => undef,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value =~ /^(\S+):(\d{2,5})$/) {
	$self->{spamcop_relayhost} = untaint_var($1);
	$self->{spamcop_relayport} = untaint_var($2);
      }
      elsif ($value =~ /^$/) {
	return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      else {
	return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
    }
  });

  $conf->{parser}->register_commands(\@cmds);
}

sub plugin_report {
  my ($self, $options) = @_;

  return unless $self->{spamcop_available};

  if (!$options->{report}->{options}->{dont_report_to_spamcop}) {
    if ($self->spamcop_report($options)) {
      $options->{report}->{report_available} = 1;
      info("reporter: spam reported to SpamCop");
      $options->{report}->{report_return} = 1;
    }
    else {
      info("reporter: could not report spam to SpamCop");
    }
  }
}

sub smtp_dbg {
  my ($command, $smtp) = @_;

  dbg("reporter: SpamCop sent $command");
  my $code = $smtp->code();
  my $message = $smtp->message();
  my $debug;
  $debug .= $code if $code;
  $debug .= ($code ? " " : "") . $message if $message;
  chomp $debug;
  dbg("reporter: SpamCop received $debug");
  return 1;
}

sub spamcop_report {
  my ($self, $options) = @_;

  # original text
  my $original = ${$options->{text}};

  # check date
  my $header = $original;
  $header =~ s/\r?\n\r?\n.*//s;
  my $date = Mail::SpamAssassin::Util::receive_date($header);
  if ($date && $date < time - 2*86400) {
    warn("reporter: SpamCop message older than 2 days, not reporting\n");
    return 0;
  }

  # message variables
  my $boundary = "----------=_" . sprintf("%08X.%08X",time,int(rand(2**32)));
  while ($original =~ /^\Q${boundary}\E$/m) {
    $boundary .= "/".sprintf("%08X",int(rand(2**32)));
  }
  my $description = "spam report via " . Mail::SpamAssassin::Version();
  my $trusted = $options->{msg}->{metadata}->{relays_trusted_str};
  my $untrusted = $options->{msg}->{metadata}->{relays_untrusted_str};
  my $user = $options->{report}->{main}->{'username'} || 'unknown';
  my $host = Mail::SpamAssassin::Util::fq_hostname() || 'unknown';
  my $from = $options->{report}->{conf}->{spamcop_from_address} || "$user\@$host";

  # message data
  my %head = (
	      'To' => $options->{report}->{conf}->{spamcop_to_address},
	      'From' => $from,
	      'Subject' => 'report spam',
	      'Date' => Mail::SpamAssassin::Util::time_to_rfc822_date(),
	      'Message-Id' =>
		sprintf("<%08X.%08X@%s>",time,int(rand(2**32)),$host),
	      'MIME-Version' => '1.0',
	      'Content-Type' => "multipart/mixed; boundary=\"$boundary\"",
	      );

  # truncate message
  if (length($original) > $self->{main}->{conf}->{spamcop_max_report_size} * 1024) {
    substr($original, ($self->{main}->{conf}->{spamcop_max_report_size} * 1024)) =
      "\n[truncated by SpamAssassin]\n";
  }

  my $body = <<"EOM";
This is a multi-part message in MIME format.

--$boundary
Content-Type: message/rfc822; x-spam-type=report
Content-Description: $description
Content-Disposition: attachment
Content-Transfer-Encoding: 8bit
X-Spam-Relays-Trusted: $trusted
X-Spam-Relays-Untrusted: $untrusted

$original
--$boundary--

EOM

  # compose message
  my $message;
  while (my ($k, $v) = each %head) {
    $message .= "$k: $v\n";
  }
  $message .= "\n" . $body;

  # send message
  my $failure;
  my $hello = Mail::SpamAssassin::Util::fq_hostname() || $from;
  $hello =~ s/.*\@//;

  my @mxs;
  if ($options->{report}->{conf}->{spamcop_relayhost}) {
    push @mxs, $options->{report}->{conf}->{spamcop_relayhost};
  } else {
    my $mx = $head{To};
    $mx =~ s/.*\@//;
    foreach my $rr (Net::DNS::mx($mx)) {
      if (defined $rr->exchange) {
        push @mxs, Mail::SpamAssassin::Util::untaint_hostname($rr->exchange);
      }
    }
    if (!@mxs) {
      warn("reporter: failed to resolve SpamCop MX servers\n");
      return 0;
    }
  }
  my $port = $options->{report}->{conf}->{spamcop_relayport} || 587;

  for my $exchange (@mxs) {
    if (my $smtp = Net::SMTP->new($exchange,
			       Hello => $hello,
			       Port => $port,
			       Timeout => 10))
    {
      if ($smtp->mail($from) && smtp_dbg("FROM $from", $smtp) &&
	  $smtp->recipient($head{To}) && smtp_dbg("TO $head{To}", $smtp) &&
	  $smtp->data($message) && smtp_dbg("DATA", $smtp) &&
	  $smtp->quit() && smtp_dbg("QUIT", $smtp))
      {
	# tell user we succeeded after first attempt if we previously failed
	warn("reporter: SpamCop report to $exchange succeeded\n") if defined $failure;
	return 1;
      }
      my $code = $smtp->code();
      my $text = $smtp->message();
      $failure = "$code $text" if ($code && $text);
    }
    $failure ||= "Net::SMTP error";
    chomp $failure;
    warn("reporter: SpamCop report to $exchange failed: $failure\n");
  }

  return 0;
}

1;

=back

=cut
