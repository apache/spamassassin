# SpamAssassin - ASN Lookup Plugin
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
###########################################################################

=head1 NAME

Mail::SpamAssassin::Plugin::ASN - SpamAssassin plugin to look up the Autonomous System Number (ASN) of the connecting IP address.

=head1 SYNOPSIS

 loadplugin Mail::SpamAssassin::Plugin::ASN

 header ASN_LOOKUP eval:asn_lookup('asn.routeviews.org', 2)

=head1 DESCRIPTION

This plugin uses DNS lookups to the services of
C<http://www.routeviews.org/> to do the actual work. Please make sure
that your use of the plugin does not overload their infrastructure -
this generally means that B<you should not use this plugin in a
high-volume environment> or that you should use a local mirror of the
zone (see C<ftp://ftp.routeviews.org/dnszones/>).

=head1 TEMPLATE TAGS

This plugin adds two tags, C<_ASN_> and C<_ASNCIDR_>, which can be
used in places where such tags can usually be used.  For example:

 add_header all ASN _ASN_ _ASNCIDR_

may add something like:

 X-Spam-ASN: AS24940 213.239.192.0/18

where "AS24940" is the ASN and "213.239.192.0/18" is the route
announced by that ASN where the connecting IP address came from. If
the AS announces multiple networks (more/less specific), they will
all be added to the C<_ASNCIDR_> tag, separated by spaces, eg:

 X-Spam-ASN: AS1680 89.138.0.0/15 89.139.0.0/16 

=head1 CONFIGURATION

The standard ruleset contains a configuration that will add a header
containing ASN data to scanned messages.  The bayes tokenizer will use the
added header for bayes calculations, and thus affect which BAYES_* rule will
trigger for a particular message.

B<Note> that in most cases you should not score on the ASN data directly.
Bayes learning will probably trigger on the _ASNCIDR_ tag, but probably not
very well on the _ASN_ tag alone.

B<Note> that the zone to lookup the ASN data in must be given as the
first parameter to the asn_lookup eval function.  This is especially 
important if you use a locally mirrored zone.

B<Note> the second parameter to asn_lookup is the number of queries to start.
This should be set to somewhere between 2 and 5 but may depend on your local
nameserver configuration.  If you run a local mirror, setting this to 1 should
probably be enough.

=head1 SEE ALSO

http://www.routeviews.org/ - all data regarding routing, ASNs etc

http://issues.apache.org/SpamAssassin/show_bug.cgi?id=4770 -
SpamAssassin Issue #4770 concerning this plugin

=head1 STATUS

Experimental - Dec. 18, 2006

No in-depth analysis of the usefulness of bayes tokenization of ASN data has
been performed.

=cut

package Mail::SpamAssassin::Plugin::ASN;

use strict;
use Mail::SpamAssassin;
use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Dns;

our @ISA = qw(Mail::SpamAssassin::Plugin);

sub new {
  my ($class, $mailsa) = @_;
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsa);
  bless ($self, $class);
  
  $self->register_eval_rule("asn_lookup");

  return $self;
}

sub asn_lookup {
  my ($self, $scanner, $zone, $num_lookups) = @_;
  if (!$scanner->is_dns_available()) {
    $self->{dns_not_available} = 1;
    return;
  } else {
    # due to re-testing dns may become available after being unavailable
    $self->{dns_not_available} = 0;
  }

  # Default to empty strings; otherwise, the tags will be left as _ASN_
  # and _ASNCIDR_ which may confuse bayes learning, I suppose.
  $scanner->{tag_data}->{ASN} = '';
  $scanner->{tag_data}->{ASNCIDR} = '';

  # We need to grab this here since the check_tick event does not
  # get *our* name, but the name of whatever rule is currently
  # being worked on.
  $scanner->{myname} = $scanner->get_current_eval_rule_name();

  my $ip = '';
  foreach my $relay (@{$scanner->{relays_untrusted}}) {
    if ($relay->{ip_private}) {
      dbg("ASN: skipping untrusted relay $relay->{ip}, it's private");
    } else {
      $ip = $relay->{ip};
      last;
    }
  }
  
  if ($ip eq '') {
    dbg("ASN: $scanner->{myname}: No IP address from relays_external");
    return;
  } else {
    dbg("ASN: $scanner->{myname}: external IP address $ip");
  }
  
  my $lookup = '';
  if ($ip =~ /^(\d+)\.(\d+)\.(\d+)\.(\d+)$/) {
    $lookup = "$4.$3.$2.$1.$zone";
  }
  
  if ($lookup eq '') {
    dbg("ASN: $scanner->{myname}: $ip does not look like an IP address");
    return;
  } else {
    dbg("ASN: $scanner->{myname}: will look up $lookup");
  }

  # DNS magic - start the lookup and have the Net::DNS package
  # store the result in our own structure
  for (my $i = 0; $i < $num_lookups; $i++) {
    $scanner->{main}->{resolver}->bgsend($lookup, 'TXT', undef, sub {
      my $pkt = shift;
      my $id = shift;
      $scanner->{asnlookup} = $pkt;
    });
  }
  
  return;
}

sub check_tick {
  my ($self, $opts) = @_;

  return if ($self->{dns_not_available});

  my $pms = $opts->{permsgstatus};

  # This will be defined if Net::DNS had something to deliver (see
  # ->bgsend() in sub asn_lookup() above)
  if ($pms->{asnlookup}) {
  
    # The regular Net::DNS dance around RRs; make sure to delete
    # the asnlookup structure, otherwise we would re-do on each
    # call of check_tick
    my $packet = delete $pms->{asnlookup};
    my @answer = $packet->answer;
    foreach my $rr (@answer) {
      dbg("ASN: $pms->{myname}: lookup result packet: " . $rr->string);
      if ($rr->type eq 'TXT') {
        my @items = split(/ /, $rr->txtdata);
        $pms->{tag_data}->{ASN} = sprintf('AS%s', $items[0]);
        my $c = sprintf('%s/%s ', $items[1], $items[2]);
        if (!($pms->{tag_data}->{ASNCIDR} =~ /$c/)) {
          $pms->{tag_data}->{ASNCIDR} .= $c;
        }
        
        # We are calling the internal _handle_hit because we want the
        # score to be zero, but still show it up in the report
        # 20061217 - disabled,will give score anyway :/
        # $pms->_handle_hit($pms->{myname}, 0.001, sprintf('AS%s %s/%s', @items));
      }
    }
  }

  return;
}

1;
