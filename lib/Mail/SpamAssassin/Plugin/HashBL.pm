# Author: Steve Freegard <steve.freegard@fsl.com>
# Copyright 2016 Steve Freegard
#
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
#

=head1 NAME

HashBL - seearch email addresses in HashBL blocklists

=head1 SYNOPSIS

  loadplugin Mail::SpamAssassin::Plugin::HashBL
  header   HASHBL_EMAIL       eval:check_hashbl_emails('ebl.msbl.org')
  describe HASHBL_EMAIL       Message contains email address found on EBL

=head1 DESCRIPTION

The Email Blocklist (EBL) contains email addresses used to receive responses to spam emails.
These email addresses are sometimes called contact email addresses or 
drop boxes.
The initial target of this blocklist was "Nigerian" 419 Advance Fee Fraud spam. As time passed and more types of spam that used drop boxes was identified, 
these drop boxes also were listed.
The EBL now lists significant numbers of drop boxes used in spam sent 
by Chinese manufacturers of high-tech and light industrial products, 
SEO/web development companies, direct spam services, list sellers, and a number
of fraudulent or outright illegal products sold by botnets.

=cut

package Mail::SpamAssassin::Plugin::HashBL;
use strict;
use warnings;
my $VERSION = 0.001;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::PerMsgStatus;
use Mail::SpamAssassin::Util;
use Digest::SHA qw(sha1_hex);
use Digest::MD5 qw(md5_hex);

use vars qw(@ISA $email_whitelist $skip_replyto_envfrom);
@ISA = qw(Mail::SpamAssassin::Plugin);

sub dbg { Mail::SpamAssassin::Plugin::dbg ("HashBL: @_"); }

sub new {
    my ($class, $mailsa) = @_;

    $class = ref($class) || $class;
    my $self = $class->SUPER::new($mailsa);
    bless ($self, $class);

    $self->{hashbl_available} = 1;
    $self->set_config($mailsa->{conf});
    $self->register_eval_rule("check_hashbl_emails");

    # Need to init the regex here, utilizing registryboundaries->valid_tlds_re
    # Some regexp tips courtesy of http://www.regular-expressions.info/email.html
    # full email regex v0.02
    $self->{email_regex} = qr/
      (?=.{0,64}\@)				# limit userpart to 64 chars (and speed up searching?)
      (?<![a-z0-9!#\$%&'*+\/=?^_`{|}~-])	# start boundary
      (						# capture email
      [a-z0-9!#\$%&'*+\/=?^_`{|}~-]+		# no dot in beginning
      (?:\.[a-z0-9!#\$%&'*+\/=?^_`{|}~-]+)*	# no consecutive dots, no ending dot
      \@
      (?:[a-z0-9](?:[a-z0-9-]{0,59}[a-z0-9])?\.){1,4} # max 4x61 char parts (should be enough?)
      $self->{main}->{registryboundaries}->{valid_tlds_re}	# ends with valid tld
      )
      (?!(?:[a-z0-9-]|\.[a-z0-9]))		# make sure domain ends here
    /xi;

    return $self;
}

sub set_config {
    my ($self, $conf) = @_;
    my @cmds;
}

sub parse_config {
    my ($self, $opts) = @_;
    return 0;
}

sub _parse_headers {
    my ($self, $pms) = @_;

    if (not defined $pms->{hashbl_email_cache}) {
        %{$pms->{hashbl_email_cache}{'headers'}} = ();
    }

    my @headers = ('EnvelopeFrom', 'Sender', 'From', 'Reply-To');

    foreach my $header (@headers) {
        my $email = $pms->get($header . ':addr');
        if ($email) {
            dbg("Found email $email in header $header");
            $pms->{hashbl_email_cache}{'headers'}{$email} = 1;
        }
    }

    return 1;
}

sub _parse_body {
    my ($self, $pms) = @_;

    # Parse body
    if (not defined $pms->{hashbl_email_cache}) {
        %{$pms->{hashbl_email_cache}{'body'}} = ();
    }

    my %seen;
    my @body_emails;
    # get all <a href="mailto:", since they don't show up on stripped_body
    my $parsed = $pms->get_uri_detail_list();
    while (my($uri, $info) = each %{$parsed}) {
        if (defined $info->{types}->{a} and not defined $info->{types}->{parsed}) {
            if ($uri =~ /^(?:(?i)mailto):$self->{email_regex}/) {
                my $email = lc($1);
                push(@body_emails, $email) unless defined $seen{$email};
                $seen{$email} = 1;
                last if scalar @body_emails >= 20; # sanity
            }
        }
    }
    # scan stripped normalized body
    # have to do this way since get_uri_detail_list doesn't know what mails are inside <>
    my $body = $pms->get_decoded_stripped_body_text_array();
    BODY: foreach (@$body) {
        # strip urls with possible emails inside
        s#<?https?://\S{0,255}(?:\@|%40)\S{0,255}# #gi;
        # strip emails contained in <>, not mailto:
        # also strip ones followed by quote-like "wrote:" (but not fax: and tel: etc)
        s#<?(?<!mailto:)$self->{email_regex}(?:>|\s{1,10}(?!(?:fa(?:x|csi)|tel|phone|e?-?mail))[a-z]{2,11}:)# #gi;
        while (/$self->{email_regex}/g) {
            my $email = lc($1);
            push(@body_emails, $email) unless defined $seen{$email};
            $seen{$email} = 1;
            last BODY if scalar @body_emails >= 40; # sanity
        }
    }
    foreach my $email (@body_emails) {
        dbg("Found email $email in body");
        $pms->{hashbl_email_cache}{'body'}{$email} = 1;
    }
    
    return 1;
}

sub _got_hit {
    my ($self, $pms, $rulename, $email, $desc) = @_;

    if (defined $pms->{conf}->{descriptions}->{$rulename}) {
        $desc = $pms->{conf}->{descriptions}->{$rulename};
    }

    $email =~ s/\@/[at]/g;
    $pms->got_hit($rulename, "", description => $desc." ($email)", ruletype => 'eval');
}

sub _submit_email_query {
    my ($self, $pms, $list, $type, $email) = @_;
    my $rulename = $pms->get_current_eval_rule_name();
    my ($hash, $lookup, $key);
    if (uc($type) eq 'SHA1') {
        $hash = sha1_hex($email);
    }
    elsif (uc($type) eq 'MD5') {
        $hash = md5_hex($email);
    }
    $lookup = "$hash.$list.";
    my $obj = { email => $email };
    dbg("list: $list, type: $type, email: $email, hash: $hash, lookup: $lookup");
    $key = "HASHBL_EMAIL:$lookup";
    my $ent = {
        key => $key,
        zone => $list,
        obj => $obj,
        type => 'HASHBL',
        rulename => $rulename,
    };

    $ent = $pms->{async}->bgsend_and_start_lookup($lookup, 'A', undef, $ent, sub {
        my ($ent2, $pkt) = @_;
        $self->_finish_email_lookup($pms, $ent2, $pkt);
    }, master_deadline => $pms->{master_deadline} );

    return $ent;   
}

sub _finish_email_lookup {
  my ($self, $pms, $ent, $pkt) = @_;

  if (!$pkt) {
      # $pkt will be undef if the DNS query was aborted (e.g. timed out)
      dbg("_finish_email_lookup aborted: ",
          $ent->{rulename}, $ent->{key});
      return;
  }

  my $email = $ent->{obj}->{email};

  dbg("_finish_email_lookup: ", $ent->{rulename}, $ent->{key}, $email);
 
  my @answer = $pkt->answer;
  foreach my $rr (@answer) {
      if ($rr->address =~ /^127\./) {
          $self->_got_hit($pms, $ent->{rulename}, $email);
          $pms->register_async_rule_finish($ent->{rulename});
      }
  }
}

sub check_hashbl_emails {
    my ($self, $pms, $list, $type) = @_;

    return 0 unless $self->{hashbl_available};

    my $rulename = $pms->get_current_eval_rule_name();

    # First we lookup all unique email addresses found in the headers
    return 0 unless $self->_parse_headers($pms);
    foreach my $email (keys %{$pms->{hashbl_email_cache}{'headers'}}) {
        # Remove this from the body hash
        delete $pms->{hashbl_email_cache}{'body'}{$email};
        dbg("HEADER: $email");
        $self->_submit_email_query($pms, $list, (($type) ? $type : 'SHA1'), $email);
    }

    # Check any e-mail addresses found in the message body
    return 0 unless $self->_parse_body($pms);

    my (@emails) = keys %{$pms->{hashbl_email_cache}{'body'}};

    # Randomize order and truncate the array to 10 items maximum
    Mail::SpamAssassin::Util::fisher_yates_shuffle(\@emails);
    $#emails = 9 if (scalar @emails > 10);

    foreach my $email (@emails) {
        #$self->_got_hit($pms, $email, "Email found in list $list");
        dbg("BODY: $email");
        $self->_submit_email_query($pms, $list, (($type) ? $type : 'SHA1'), $email);
    }

    return 0;
}

1;
