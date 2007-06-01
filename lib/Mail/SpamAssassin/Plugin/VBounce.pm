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

Mail::SpamAssassin::Plugin::VBounce

=head1 SYNOPSIS

 loadplugin Mail::SpamAssassin::Plugin::VBounce [/path/to/VBounce.pm]

=cut

package Mail::SpamAssassin::Plugin::VBounce;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use strict;
use warnings;

our @ISA = qw(Mail::SpamAssassin::Plugin);

sub new {
  my $class = shift;
  my $mailsaobject = shift;

  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->register_eval_rule("have_any_bounce_relays");
  $self->register_eval_rule("check_whitelist_bounce_relays");

  $self->set_config($mailsaobject->{conf});

  return $self;
}

sub set_config {
  my($self, $conf) = @_;
  my @cmds = ();

=head1 USER PREFERENCES

The following options can be used in both site-wide (C<local.cf>) and
user-specific (C<user_prefs>) configuration files to customize how
SpamAssassin handles incoming email messages.

=over 4

=item whitelist_bounce_relays hostname [hostname2 ...]

This is used to 'rescue' legitimate bounce messages that were generated in
response to mail you really *did* send.  List the MTA relays that your outbound
mail is delivered through.  If a bounce message is found, and it contains one
of these hostnames in a 'Received' header, it will not be marked as a blowback
virus-bounce.

The hostnames can be file-glob-style patterns, so C<relay*.isp.com> will work.
Specifically, C<*> and C<?> are allowed, but all other metacharacters are not.
Regular expressions are not used for security reasons.

Multiple addresses per line, separated by spaces, is OK.  Multiple
C<whitelist_from> lines is also OK.


=cut

  push (@cmds, {
      setting => 'whitelist_bounce_relays',
      type => $Mail::SpamAssassin::Conf::CONF_TYPE_ADDRLIST
    });

  $conf->{parser}->register_commands(\@cmds);
}

sub have_any_bounce_relays {
  my ($self, $pms) = @_;
  return (defined $pms->{conf}->{whitelist_bounce_relays} &&
      (scalar values %{$pms->{conf}->{whitelist_bounce_relays}} != 0));
}

sub check_whitelist_bounce_relays {
  my ($self, $pms) = @_;

  my $body = $pms->get_decoded_stripped_body_text_array();
  my $res;

  # catch lines like:
  # Received: by dogma.boxhost.net (Postfix, from userid 1007)

  # check the plain-text body, first
  foreach my $line (@{$body}) {
    next unless ($line =~ /Received: /);
    while ($line =~ / (\S+\.\S+) /g) {
      return 1 if $self->_relay_is_in_whitelist_bounce_relays($pms, $1);
    }
  }

  # now check any "message/anything" attachment MIME parts, too.
  # don't use the more efficient find_parts() method until bug 5331 is
  # fixed, otherwise we'll miss some messages due to their MIME structure
  
  my $pristine = $pms->{msg}->get_pristine();
  # skip past the headers
  my $foundnlnl = 0;
  foreach my $line ($pristine =~ /^(.*)$/gm) {
    # note: do not use any re match here, it'll reset /g
    if ($line eq "" || $line eq "\012" || $line eq "\015\012") {
      $foundnlnl = 1; last;
    }
  }
  return 0 unless $foundnlnl;

  # and now through the pristine body
  foreach my $line ($pristine =~ /^(.*)$/gm) {
    next unless $line && ($line =~ /Received: /);
    while ($line =~ / (\S+\.\S+) /g) {
      return 1 if $self->_relay_is_in_whitelist_bounce_relays($pms, $1);
    }
  }

  return 0;
}

sub _relay_is_in_whitelist_bounce_relays {
  my ($self, $pms, $relay) = @_;
  return 1 if $self->_relay_is_in_list(
        $pms->{conf}->{whitelist_bounce_relays}, $pms, $relay);
  dbg("rules: relay $relay doesn't match any whitelist");
}

sub _relay_is_in_list {
  my ($self, $list, $pms, $relay) = @_;
  $relay = lc $relay;

  if (defined $list->{$relay}) { return 1; }

  foreach my $regexp (values %{$list}) {
    if ($relay =~ qr/$regexp/i) {
      dbg("rules: relay $relay matches regexp: $regexp");
      return 1;
    }
  }

  return 0;
}

1;
__DATA__

=back

=cut

