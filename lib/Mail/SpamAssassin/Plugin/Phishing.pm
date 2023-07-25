#
# Author: Giovanni Bechis <gbechis@apache.org>
# Copyright 2018,2020 Giovanni Bechis
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
OpenPhish, PhishTank or PhishStats feeds.

The Openphish free feed is updated every 6 hours and can be downloaded from
https://openphish.com/feed.txt.

The PhishTank free feed is updated every 1 hours and can be downloaded from
http://data.phishtank.com/data/online-valid.csv.
To avoid download limits a registration is required.

=cut

package Mail::SpamAssassin::Plugin::Phishing;
use strict;
use warnings;
use re 'taint';

my $VERSION = 1.1;

use Errno qw(EBADF);
use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::PerMsgStatus;

our @ISA = qw(Mail::SpamAssassin::Plugin);

sub dbg { my $msg = shift; Mail::SpamAssassin::Plugin::dbg("Phishing: $msg", @_); }

sub new {
    my ($class, $mailsa) = @_;

    $class = ref($class) || $class;
    my $self = $class->SUPER::new($mailsa);
    bless ($self, $class);

    $self->set_config($mailsa->{conf});
    $self->register_eval_rule("check_phishing", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);

    return $self;
}

sub set_config {
    my ($self, $conf) = @_;
    my @cmds;
    push(@cmds, {
        setting => 'phishing_openphish_feed',
        is_admin => 1,
        type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
        }
    );

=head1 ADMIN PREFERENCES

The following options can be used in site-wide (C<local.cf>)
configuration files to customize how the module handles phishing uris

=cut

=over 4

=item phishing_openphish_feed

Absolute path of the downloaded OpenPhish datafeed.

=back

=cut
    push(@cmds, {
        setting => 'phishing_phishtank_feed',
        is_admin => 1,
        type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
        }
    );

=over 4

=item phishing_phishtank_feed

Absolute path of the downloaded PhishTank datafeed.

=back

=cut
    push(@cmds, {
        setting => 'phishing_uri_noparam',
        is_admin => 1,
        default => 0,
        type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL,
        }
    );

=over 4

=item phishing_uri_noparam ( 0 | 1 ) (default: 0)

If this option is set uri parameters will not be take into consideration
when parsing the phishing uris datafeed.
If this option is enabled and the url without parameters is "generic"
(like https://www.kisa.link/url_redirector.php?url=...) the url will be
skipped.

=back

=cut
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
  my $stripped_cluri;

  local *F;
  if ( defined($conf->{phishing_openphish_feed}) && ( -f $conf->{phishing_openphish_feed} ) ) {
    open(F, '<', $conf->{phishing_openphish_feed});
    for ($!=0; <F>; $!=0) {
        chomp;
        #lines that start with pound are comments
        next if(/^\s*\#/);
        $stripped_cluri = $_;
	if ( $conf->{phishing_uri_noparam} eq 1 ) {
          $stripped_cluri =~ s/\?.*//;
	}
        my $phishdomain = $self->{main}->{registryboundaries}->uri_to_domain($_);
        if ( defined $phishdomain ) {
          push @{$self->{PHISHING}->{$stripped_cluri}->{phishdomain}}, $phishdomain;
          push @{$self->{PHISHING}->{$stripped_cluri}->{phishinfo}->{$phishdomain}}, "OpenPhish";
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
        $stripped_cluri = $phtank_ln[1];
	if ( $conf->{phishing_uri_noparam} eq 1 ) {
          $stripped_cluri =~ s/\?.*//;
	}
        my $phishdomain = $self->{main}->{registryboundaries}->uri_to_domain($phtank_ln[1]);
        if ( defined $phishdomain ) {
          push @{$self->{PHISHING}->{$stripped_cluri}->{phishdomain}}, $phishdomain;
          push @{$self->{PHISHING}->{$stripped_cluri}->{phishinfo}->{$phishdomain}}, "PhishTank";
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
  my $stripped_cluri;
  my $dcnt;

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
        $stripped_cluri = $cluri;
	if( $self->{main}->{conf}->{phishing_uri_noparam} eq 1 ) {
          $stripped_cluri =~ s/\?.*//;
          $dcnt = $stripped_cluri =~ tr/\///;
	}
	# If uri without parameters are considered, skip too short uris
	# like https://www.google.com/url?sa=t&url=http://badsite.com
        if( ($self->{main}->{conf}->{phishing_uri_noparam} eq 1) && ($dcnt <= 3) ) {
          next;
        }
        if ( exists $self->{PHISHING}->{$stripped_cluri} ) {
          $domain = $self->{main}->{registryboundaries}->uri_to_domain($cluri);
          $feedname = $self->{PHISHING}->{$stripped_cluri}->{phishinfo}->{$domain}[0];
          dbg("HIT! $domain [$stripped_cluri] found in $feedname feed");
          $pms->test_log("$feedname ($domain)", $rulename);
          return 1;
        }
      }
    }
   }
  return 0;
}

1;
