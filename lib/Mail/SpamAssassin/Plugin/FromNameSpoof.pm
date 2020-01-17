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

FromNameSpoof - perform various tests to detect spoof attempts using the From header name section

=head1 SYNOPSIS

loadplugin    Mail::SpamAssassin::Plugin::FromNameSpoof

 # Does the From:name look like it contains an email address
 header   __PLUGIN_FROMNAME_EMAIL  eval:check_fromname_contains_email()

 # Is the From:name different to the From:addr header
 header   __PLUGIN_FROMNAME_DIFFERENT  eval:check_fromname_different()

 # From:name and From:addr owners differ
 header   __PLUGIN_FROMNAME_OWNERS_DIFFER  eval:check_fromname_owners_differ()

 # From:name domain differs to from header
 header   __PLUGIN_FROMNAME_DOMAIN_DIFFER  eval:check_fromname_domain_differ()

 # From:name and From:address don't match and owners differ
 header   __PLUGIN_FROMNAME_SPOOF  eval:check_fromname_spoof()
  
 # From:name address matches To:address
 header __PLUGIN_FROMNAME_EQUALS_TO  eval:check_fromname_equals_to()

=head1 DESCRIPTION

Perform various tests against From:name header to detect spoofing. Steps in place to 
ensure minimal FPs.

=head1 CONFIGURATION

The plugin allows you to skip emails that have been DKIM signed by specific senders:

 fns_ignore_dkim googlegroups.com

FromNameSpoof allows for a configurable closeness when matching the From:addr and From:name,
the closeness can be adjusted with:

 fns_extrachars 50

B<Note> that FromNameSpoof detects the "owner" of a domain by the following search:

 <owner>.<tld>

By default FromNameSpoof will ignore the TLD when testing if From:addr is spoofed.
Default 1

  fns_check 1

Check levels:

 0 - Strict checking of From:name != From:addr
 1 - Allow for different tlds
 2 - Allow for different aliases but same domain

=head1 TAGS

The following tags are added to the set if a spoof is detected. They are available for 
use in reports, header fields, other plugins, etc.:

  _FNSFNAMEADDR_
    Detected spoof address from From:name header

  _FNSFNAMEDOMAIN_
    Detected spoof domain from From:name header

  _FNSFNAMEOWNER_
    Detected spoof owner from From:name header

  _FNSFADDRADDR_
    Actual From:addr address

  _FNSFADDRDOMAIN_ 
    Actual From:addr domain

  _FNSFADDROWNER_
    Actual From:addr detected owner

=head1 EXAMPLE 

header   __PLUGIN_FROMNAME_SPOOF eval:check_fromname_spoof()
header   __PLUGIN_FROMNAME_EQUALS_TO eval:check_fromname_equals_to()

meta     FROMNAME_SPOOF_EQUALS_TO  (__PLUGIN_FROMNAME_SPOOF && __PLUGIN_FROMNAME_EQUALS_TO)
describe FROMNAME_SPOOF_EQUALS_TO From:name is spoof to look like To: address
score    FROMNAME_SPOOF_EQUALS_TO 1.2

=cut

use strict;

package Mail::SpamAssassin::Plugin::FromNameSpoof;
my $VERSION = 0.9;

use Mail::SpamAssassin::Plugin;
use List::Util ();
use Mail::SpamAssassin::Util;

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

sub dbg { Mail::SpamAssassin::Plugin::dbg ("FromNameSpoof: @_"); }

sub uri_to_domain {
  my ($self, $domain) = @_;

  return unless defined $domain;

  if ($Mail::SpamAssassin::VERSION <= 3.004000) {
    Mail::SpamAssassin::Util::uri_to_domain($domain);
  } else {
    $self->{main}->{registryboundaries}->uri_to_domain($domain);
  }
}

# constructor: register the eval rule
sub new
{
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->set_config($mailsaobject->{conf});

  # the important bit!
  $self->register_eval_rule("check_fromname_spoof");
  $self->register_eval_rule("check_fromname_different");
  $self->register_eval_rule("check_fromname_domain_differ");
  $self->register_eval_rule("check_fromname_contains_email");
  $self->register_eval_rule("check_fromname_equals_to");
  $self->register_eval_rule("check_fromname_owners_differ");
  $self->register_eval_rule("check_fromname_equals_replyto");
  return $self;
}

sub set_config {
  my ($self, $conf) = @_;
  my @cmds = ();

  push (@cmds, {
    setting => 'fns_add_addrlist',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_ADDRLIST,
    code => sub {
      my($self, $key, $value, $line) = @_;
      local($1,$2);
      if ($value !~ /^ \( (.*?) \) \s+ (.*) \z/sx) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      my $listname = "FNS_$1";
      $value = $2;
      $self->{parser}->add_to_addrlist ($listname, split(/\s+/, lc($value)));
      $self->{fns_addrlists}{$listname} = 1;
    }
  });

  push (@cmds, {
    setting => 'fns_remove_addrlist',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_ADDRLIST,
    code => sub {
      my($self, $key, $value, $line) = @_;
      local($1,$2);
      if ($value !~ /^ \( (.*?) \) \s+ (.*) \z/sx) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      my $listname = "FNS_$1";
      $value = $2;
      $self->{parser}->remove_from_addrlist ($listname, split (/\s+/, $value));
    }
  });

  push(@cmds, {
    setting => 'fns_extrachars',
    default => 50,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });

  push (@cmds, {
    setting => 'fns_ignore_dkim',
    default => {},
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value eq '') {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      $self->{fns_ignore_dkim}->{$_} = 1 foreach (split(/\s+/, lc($value)));
    }
  });

  push (@cmds, {
    setting => 'fns_ignore_headers',
    default => {},
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value eq '') {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      $self->{fns_ignore_header}->{$_} = 1 foreach (split(/\s+/, $value));
    }
  });

  push(@cmds, {
    setting => 'fns_check',
    default => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });

  $conf->{parser}->register_commands(\@cmds);
}

sub parsed_metadata {
  my ($self, $opts) = @_;
  my $pms = $opts->{permsgstatus};
  $pms->action_depends_on_tags('DKIMDOMAIN',
      sub { my($pms,@args) = @_;
        $self->_check_fromnamespoof($pms);
      }
  );
  1;
}

sub check_fromname_different
{
  my ($self, $pms) = @_;
  $self->_check_fromnamespoof($pms);
  return $pms->{fromname_address_different};
}

sub check_fromname_domain_differ
{
  my ($self, $pms) = @_;
  $self->_check_fromnamespoof($pms);
  return $pms->{fromname_domain_different};
}

sub check_fromname_spoof
{
  my ($self, $pms, $check_lvl) = @_;
  $self->_check_fromnamespoof($pms);

  if ( not defined $check_lvl ) {
    $check_lvl = $pms->{conf}->{fns_check};
  }

  my @array = (
    ($pms->{fromname_address_different}) ,
    ($pms->{fromname_address_different} && $pms->{fromname_owner_different}) ,
    ($pms->{fromname_address_different} && $pms->{fromname_domain_different})
  );

  return $array[$check_lvl];

}

sub check_fromname_contains_email
{
  my ($self, $pms) = @_;
  $self->_check_fromnamespoof($pms);
  return $pms->{fromname_contains_email};
}

sub check_fromname_equals_replyto
{
  my ($self, $pms) = @_;
  $self->_check_fromnamespoof($pms);
  return $pms->{fromname_equals_replyto};
}

sub check_fromname_equals_to
{
  my ($self, $pms) = @_;
  $self->_check_fromnamespoof($pms);
  return $pms->{fromname_equals_to_addr};
}

sub check_fromname_owners_differ
{
  my ($self, $pms) = @_;
  $self->_check_fromnamespoof($pms);
  return $pms->{fromname_owner_different};
}

sub _check_fromnamespoof
{
  my ($self, $pms) = @_;

  return if (defined $pms->{fromname_contains_email});

  my $conf = $pms->{conf};

  $pms->{fromname_contains_email} = 0;
  $pms->{fromname_address_different} = 0;
  $pms->{fromname_equals_to_addr} = 0;
  $pms->{fromname_domain_different} = 0;
  $pms->{fromname_owner_different} = 0;
  $pms->{fromname_equals_replyto} = 0;

  foreach my $addr (split / /, $pms->get_tag('DKIMDOMAIN') || '') {
    if ($conf->{fns_ignore_dkim}->{lc($addr)}) {
      dbg("ignoring, DKIM signed: $addr");
      return 0;
    }
  }

  foreach my $iheader (keys %{$conf->{fns_ignore_header}}) {
    if ($pms->get($iheader)) {
      dbg("ignoring, header $iheader found");
      return 0 if ($pms->get($iheader));
    }
  }

  my $list_refs = {};

  if ($conf->{fns_addrlists}) {
    my @lists = keys %{$conf->{fns_addrlists}};
    foreach my $list (@lists) {
      $list_refs->{$list} = $conf->{$list};
    }
    s/^FNS_// foreach (@lists);
    dbg("using addrlists: ".join(', ', @lists));
  }

  my %fnd = ();
  my %fad = ();
  my %tod = ();

  $fnd{'addr'} = $pms->get("From:name");

  if ($fnd{'addr'} =~ /\b((?>[\w\.\!\#\$\%\&\'\*\+\/\=\?\^\_\`\{\|\}\~\-]+@[\w\-\.]+\.[\w\-\.]+))\b/i) {
    my $nochar = ($fnd{'addr'} =~ y/A-Za-z0-9//c);
    $nochar -= ($1 =~ y/A-Za-z0-9//c);

    return 0 unless ((length($fnd{'addr'})+$nochar) - length($1) <= $conf->{'fns_extrachars'});

    $fnd{'addr'} = lc $1;
  } else {
    return 0;
  }

  my $replyto = lc $pms->get("Reply-To:addr");

  $fad{'addr'} = lc $pms->get("From:addr");
  my @toaddrs = $pms->all_to_addrs();
  return 0 unless @toaddrs;

  $tod{'addr'} = lc $toaddrs[0];

  $fnd{'domain'} = $self->uri_to_domain($fnd{'addr'});
  $fad{'domain'} = $self->uri_to_domain($fad{'addr'});
  $tod{'domain'} = $self->uri_to_domain($tod{'addr'});

  return 0 unless (defined $fnd{'domain'} && defined $fad{'domain'});

  $pms->{fromname_contains_email} = 1;

  $fnd{'owner'} = $self->_find_address_owner($fnd{'addr'}, $list_refs);

  $fad{'owner'} = $self->_find_address_owner($fad{'addr'}, $list_refs);

  $tod{'owner'} = $self->_find_address_owner($tod{'addr'}, $list_refs);

  $pms->{fromname_address_different} = 1 if ($fnd{'addr'} ne $fad{'addr'});

  $pms->{fromname_domain_different} = 1 if ($fnd{'domain'} ne $fad{'domain'});

  $pms->{fromname_equals_to_addr} = 1 if ($fnd{'addr'} eq $tod{addr});

  $pms->{fromname_equals_replyto} = 1 if ($fnd{'addr'} eq $replyto);

  if ($fnd{'owner'} ne $fad{'owner'}) {
    $pms->{fromname_owner_different} = 1;
  }

  if ($pms->{fromname_address_different}) {
    $pms->set_tag("FNSFNAMEADDR", $fnd{'addr'});
    $pms->set_tag("FNSFADDRADDR", $fad{'addr'});
    $pms->set_tag("FNSFNAMEOWNER", $fnd{'owner'});
    $pms->set_tag("FNSFADDROWNER", $fad{'owner'});
    $pms->set_tag("FNSFNAMEDOMAIN", $fnd{'domain'});
    $pms->set_tag("FNSFADDRDOMAIN", $fad{'domain'});

    dbg("From name spoof: $fnd{addr} $fnd{domain} $fnd{owner}");
    dbg("Actual From: $fad{addr} $fad{domain} $fad{owner}");
    dbg("To Address: $tod{addr} $tod{domain} $tod{owner}");
  }
}

sub _find_address_owner
{
  my ($self, $check, $list_refs) = @_;
  foreach my $owner (keys %{$list_refs}) {
    foreach my $white_addr (keys %{$list_refs->{$owner}}) {
      my $regexp = qr/$list_refs->{$owner}{$white_addr}/i;
      if ($check =~ /$regexp/)  {
        $owner =~ s/^FNS_//i;
        return lc $owner;
      }
    }
  }

  my $owner = $self->uri_to_domain($check);

  $check =~ /^([^\@]+)\@(.*)$/;

  if ($owner ne $2) {
    return $self->_find_address_owner("$1\@$owner", $list_refs);
  }

  $owner =~ /^([^\.]+)\./;
  return lc $1;
}

1;
