#
# Author: Giovanni Bechis <gbechis@apache.org>
# Copyright 2018,2019 Giovanni Bechis
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

Mail::SpamAssassin::Plugin::Phishing - check uris against phishing feed

=head1 SYNOPSIS

  loadplugin Mail::SpamAssassin::Plugin::Phishing

  ifplugin Mail::SpamAssassin::Plugin::Phishing
    phishing_openphish_feed /etc/mail/spamassassin/openphish-feed.txt
    phishing_phishtank_feed /etc/mail/spamassassin/phishtank-feed.csv
    body     URI_PHISHING      eval:check_phishing()
    describe URI_PHISHING      Url match phishing in feed
  endif

=head1 DESCRIPTION

This plugin finds uris used in phishing campaigns detected by 
OpenPhish or PhishTank feeds.

The Openphish free feed is updated every 6 hours and can be downloaded from
https://openphish.com/feed.txt.
The Premium Openphish feed is not currently supported.

The PhishTank free feed is updated every 1 hours and can be downloaded from
http://data.phishtank.com/data/online-valid.csv.
To avoid download limits a registration is required.

=cut

package Mail::SpamAssassin::Plugin::Phishing;
use strict;
use warnings;
my $VERSION = 1.1;

use Errno qw(EBADF);
use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::PerMsgStatus;

our @ISA = qw(Mail::SpamAssassin::Plugin);

sub dbg { Mail::SpamAssassin::Plugin::dbg ("Phishing: @_"); }

sub new {
    my ($class, $mailsa) = @_;

    $class = ref($class) || $class;
    my $self = $class->SUPER::new($mailsa);
    bless ($self, $class);

    $self->set_config($mailsa->{conf});
    $self->register_eval_rule("check_phishing");

    return $self;
}

sub set_config {
    my ($self, $conf) = @_;
    my @cmds;
    push(@cmds, {
        setting => 'phishing_openphish_feed',
        type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
        }
    );
    push(@cmds, {
        setting => 'phishing_phishtank_feed',
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
  my @phtank_ln;

  local *F;
  if ( defined($conf->{phishing_openphish_feed}) && ( -f $conf->{phishing_openphish_feed} ) ) {
    open(F, '<', $conf->{phishing_openphish_feed});
    for ($!=0; <F>; $!=0) {
        chomp;
        #lines that start with pound are comments
        next if(/^\s*\#/);
        my $phishdomain = $self->{main}->{registryboundaries}->uri_to_domain($_);
        if ( defined $phishdomain ) {
          push @{$self->{PHISHING}->{$_}->{phishdomain}}, $phishdomain;
          push @{$self->{PHISHING}->{$_}->{phishinfo}->{$phishdomain}}, "OpenPhish";
        }
    }

    defined $_ || $!==0  or
      $!==EBADF ? dbg("PHISHING: error reading config file: $!")
                : die "error reading config file: $!";
    close(F) or die "error closing config file: $!";
  }

  if ( defined($conf->{phishing_phishtank_feed}) && (-f $conf->{phishing_phishtank_feed} ) ) {
    open(F, '<', $conf->{phishing_phishtank_feed});
    for ($!=0; <F>; $!=0) {
        #skip first line
        next if ( $. eq 1);
        chomp;
        #lines that start with pound are comments
        next if(/^\s*\#/);

        @phtank_ln = split(/,/, $_);
        $phtank_ln[1] =~ s/\"//g;

        my $phishdomain = $self->{main}->{registryboundaries}->uri_to_domain($phtank_ln[1]);
        if ( defined $phishdomain ) {
          push @{$self->{PHISHING}->{$phtank_ln[1]}->{phishdomain}}, $phishdomain;
          push @{$self->{PHISHING}->{$phtank_ln[1]}->{phishinfo}->{$phishdomain}}, "PhishTank";
        }
    }

    defined $_ || $!==0  or
      $!==EBADF ? dbg("PHISHING: error reading config file: $!")
                : die "error reading config file: $!";
    close(F) or die "error closing config file: $!";
  }
}

sub check_phishing {
  my ($self, $pms) = @_;

  my $feedname;
  my $domain;
  my $uris = $pms->get_uri_detail_list();

  my $rulename = $pms->get_current_eval_rule_name();

  while (my($uri, $info) = each %{$uris}) {
    # we want to skip mailto: uris
    next if ($uri =~ /^mailto:/i);

    # no hosts/domains were found via this uri, so skip
    next unless ($info->{hosts});
    if (($info->{types}->{a}) || ($info->{types}->{parsed})) {
      # check url
      foreach my $cluri (@{$info->{cleaned}}) {
        if ( exists $self->{PHISHING}->{$cluri} ) {
          $domain = $self->{main}->{registryboundaries}->uri_to_domain($cluri);
          $feedname = $self->{PHISHING}->{$cluri}->{phishinfo}->{$domain}[0];
          dbg("HIT! $domain [$cluri] found in $feedname feed");
          $pms->test_log("$feedname ($domain)");
          $pms->got_hit($rulename, "", ruletype => 'eval');
          return 1;
        }
      }
    }
   }
  return 0;
}

1;
