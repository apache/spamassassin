# <@LICENSE>
# Copyright 2004 Apache Software Foundation
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
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

Mail::SpamAssassin::Plugin::SPF - perform SPF verification tests

=head1 SYNOPSIS

  loadplugin     Mail::SpamAssassin::Plugin::SPF

=head1 DESCRIPTION

This plugin checks a message against Sender Policy Framework (SPF)
records published by the domain owners in DNS to fight email address
forgery and make it easier to identify spams.

=cut

package Mail::SpamAssassin::Plugin::SPF;

# Make the main dbg() accessible in our package w/o an extra function
*dbg=\&Mail::SpamAssassin::Plugin::dbg;

use Mail::SpamAssassin::Plugin;
use strict;
use warnings;
use bytes;

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  my $conf = $mailsaobject->{conf};

  $self->register_eval_rule ("check_for_spf_pass");
  $self->register_eval_rule ("check_for_spf_fail");
  $self->register_eval_rule ("check_for_spf_softfail");
  $self->register_eval_rule ("check_for_spf_helo_pass");
  $self->register_eval_rule ("check_for_spf_helo_fail");
  $self->register_eval_rule ("check_for_spf_helo_softfail");

  return $self;
}

###########################################################################

# SPF support
sub check_for_spf_pass {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 0) unless $scanner->{spf_checked};
  $scanner->{spf_pass};
}

sub check_for_spf_fail {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 0) unless $scanner->{spf_checked};
  if ($scanner->{spf_failure_comment}) {
    $scanner->test_log ($scanner->{spf_failure_comment});
  }
  $scanner->{spf_fail};
}

sub check_for_spf_softfail {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 0) unless $scanner->{spf_checked};
  if ($scanner->{spf_failure_comment}) {
    $scanner->test_log ($scanner->{spf_failure_comment});
  }
  $scanner->{spf_softfail};
}

sub check_for_spf_helo_pass {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 1) unless $scanner->{spf_helo_checked};
  $scanner->{spf_helo_pass};
}

sub check_for_spf_helo_fail {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 1) unless $scanner->{spf_helo_checked};
  if ($scanner->{spf_helo_failure_comment}) {
    $scanner->test_log ($scanner->{spf_helo_failure_comment});
  }
  $scanner->{spf_helo_fail};
}

sub check_for_spf_helo_softfail {
  my ($self, $scanner) = @_;
  $self->_check_spf ($scanner, 1) unless $scanner->{spf_helo_checked};
  if ($scanner->{spf_helo_failure_comment}) {
    $scanner->test_log ($scanner->{spf_helo_failure_comment});
  }
  $scanner->{spf_helo_softfail};
}

sub _check_spf {
  my ($self, $scanner, $ishelo) = @_;

  return unless $scanner->is_dns_available();

  # skip SPF checks if the A/MX records are nonexistent for the From
  # domain, anyway, to avoid crappy messages from slowing us down
  # (bug 3016)
  return if $scanner->check_for_from_dns();

  if ($ishelo) {
    # SPF HELO-checking variant.  This isn't really SPF at all ;)
    $scanner->{spf_helo_checked} = 1;
    $scanner->{spf_helo_pass} = 0;
    $scanner->{spf_helo_fail} = 0;
    $scanner->{spf_helo_softfail} = 0;
    $scanner->{spf_helo_failure_comment} = undef;
  } else {
    # "real" SPF; checking the envelope-from (where we can)
    $scanner->{spf_checked} = 1;
    $scanner->{spf_pass} = 0;
    $scanner->{spf_fail} = 0;
    $scanner->{spf_softfail} = 0;
    $scanner->{spf_failure_comment} = undef;
  }

  my $lasthop = $scanner->{relays_untrusted}->[0];
  if (!defined $lasthop) {
    dbg("spf: message was delivered entirely via trusted relays, not required");
    return;
  }

  my $ip = $lasthop->{ip};
  my $helo = $lasthop->{helo};
  my $sender = '';

  if ($ishelo) {
    dbg("spf: checking HELO (helo=$helo, ip=$ip)");

    if ($helo !~ /^\d+\.\d+\.\d+\.\d+$/) {
      # get rid of hostname part of domain, understanding delegation
      $helo = Mail::SpamAssassin::Util::RegistrarBoundaries::trim_domain ($helo);
    }

    dbg("spf: trimmed HELO down to '$helo'");

  } else {
    $sender = $lasthop->{envfrom};

    if ($sender) {
      dbg("spf: found Envelope-From in last untrusted Received header");
    }
    else {
      # We cannot use the env-from data, since it went through 1 or
      # more relays since the untrusted sender and they may have
      # rewritten it.
      #
      if ($scanner->{num_relays_trusted} > 0) {
	dbg("spf: relayed through one or more trusted relays, cannot use header-based Envelope-From, skipping");
	return;
      }

      # we can (apparently) use whatever the current Envelope-From was,
      # from the Return-Path, X-Envelope-From, or whatever header.
      # it's better to get it from Received though, as that is updated
      # hop-by-hop.
      #
      $sender = $scanner->get ("EnvelopeFrom");
    }

    if (!$sender) {
      dbg("spf: cannot get Envelope-From, cannot use SPF");
      return;
    }
    dbg("spf: checking EnvelopeFrom (helo=$helo, ip=$ip, envfrom=$sender)");
  }

  # this test could probably stand to be more strict, but try to test
  # any invalid HELO hostname formats with a header rule
  if ($ishelo && ($helo =~ /^\d+\.\d+\.\d+\.\d+$/ || $helo =~ /^[^.]+$/)) {
    dbg("spf: cannot check HELO of '$helo', skipping");
    return;
  }
  if (!$helo) {
    dbg("spf: cannot get HELO, cannot use SPF");
    return;
  }

  if ($scanner->server_failed_to_respond_for_domain($helo)) {
    dbg("spf: we had a previous timeout on '$helo', skipping");
    return;
  }

  my $query;
  eval {
    require Mail::SPF::Query;
    if (!defined $Mail::SPF::Query::VERSION || $Mail::SPF::Query::VERSION < 1.996) {
      die "spf: Mail::SPF::Query 1.996 or later required, this is $Mail::SPF::Query::VERSION\n";
    }
    $query = Mail::SPF::Query->new (ip => $ip,
				    sender => $sender,
				    helo => $helo,
				    debug => Mail::SpamAssassin::dbg_check('+rbl'),
				    trusted => 0);
  };

  if ($@) {
    dbg("spf: cannot load or create Mail::SPF::Query module: $@");
    return;
  }

  my ($result, $comment);
  my $timeout = 5;
  my $oldalarm;

  eval {
    local $SIG{ALRM} = sub { die "__alarm__\n" };
    $oldalarm = alarm($timeout);
    ($result, $comment) = $query->result();
    alarm $oldalarm;
  };

  my $err = $@;

  if ($err) {
    alarm $oldalarm;
    if ($err =~ /^__alarm__$/) {
      dbg("spf: lookup timed out after $timeout seconds");
    } else {
      warn("spf: lookup failed: $err\n");
    }
    return 0;
  }

  $result ||= 'softfail';
  $comment ||= '';
  $comment =~ s/\s+/ /gs;	# no newlines please

  if ($ishelo) {
    if ($result eq 'pass') { $scanner->{spf_helo_pass} = 1; }
    elsif ($result eq 'fail') { $scanner->{spf_helo_fail} = 1; }
    elsif ($result eq 'softfail') { $scanner->{spf_helo_softfail} = 1; }

    if ($result eq 'fail' || $result eq 'softfail') {
      $scanner->{spf_helo_failure_comment} = "SPF failed: $comment";
    }
  } else {
    if ($result eq 'pass') { $scanner->{spf_pass} = 1; }
    elsif ($result eq 'fail') { $scanner->{spf_fail} = 1; }
    elsif ($result eq 'softfail') { $scanner->{spf_softfail} = 1; }

    if ($result eq 'fail' || $result eq 'softfail') {
      $scanner->{spf_failure_comment} = "SPF failed: $comment";
    }
  }

  dbg("spf: query for $sender/$ip/$helo: result: $result, comment: $comment");
}

###########################################################################

1;
