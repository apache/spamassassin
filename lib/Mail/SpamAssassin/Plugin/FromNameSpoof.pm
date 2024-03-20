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

FromNameSpoof - perform various tests to detect spoof attempts using the
From header name section

=head1 SYNOPSIS

loadplugin    Mail::SpamAssassin::Plugin::FromNameSpoof

 # From:name and From:addr do not match, matching depends on C<fns_check> setting
 header  __PLUGIN_FROMNAME_SPOOF  eval:check_fromname_spoof()

 # From:name and From:addr do not match (same as above rule and C<fns_check 0>)
 header  __PLUGIN_FROMNAME_DIFFERENT  eval:check_fromname_different()

 # From:name and From:addr domains differ
 header  __PLUGIN_FROMNAME_DOMAIN_DIFFER  eval:check_fromname_domain_differ()

 # From:name looks like it contains an email address (not same as From:addr)
 header  __PLUGIN_FROMNAME_EMAIL  eval:check_fromname_contains_email()

 # From:name matches any To:addr
 header  __PLUGIN_FROMNAME_EQUALS_TO  eval:check_fromname_equals_to()

 # From:name and From:addr owners differ
 header  __PLUGIN_FROMNAME_OWNERS_DIFFER  eval:check_fromname_owners_differ()

 # From:name matches Reply-To:addr
 header  __PLUGIN_FROMNAME_EQUALS_REPLYTO  eval:check_fromname_equals_replyto()

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

By default FromNameSpoof will ignore the TLD when comparing addresses:

  fns_check 1

Check levels:

  0 - Strict checking of From:name != From:addr
  1 - Allow for different TLDs
  2 - Allow for different aliases but same domain

"Owner" info can also be mapped as aliases with C<fns_add_addrlist>.  For
example, to consider "googlemail.com" as "gmail":

  fns_add_addrlist (gmail) *@googlemail.com

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
    Actual From:addr owner

=head1 EXAMPLE 

  header  __PLUGIN_FROMNAME_SPOOF  eval:check_fromname_spoof()
  header  __PLUGIN_FROMNAME_EQUALS_TO  eval:check_fromname_equals_to()
  meta     FROMNAME_SPOOF_EQUALS_TO (__PLUGIN_FROMNAME_SPOOF && __PLUGIN_FROMNAME_EQUALS_TO)
  describe FROMNAME_SPOOF_EQUALS_TO From:name is spoof to look like To: address
  score    FROMNAME_SPOOF_EQUALS_TO 1.2

=cut

package Mail::SpamAssassin::Plugin::FromNameSpoof;

use strict;
use warnings;
use re 'taint';

use Mail::SpamAssassin::Plugin;

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

my $VERSION = 1.0;

sub dbg { my $msg = shift; Mail::SpamAssassin::Plugin::dbg("FromNameSpoof: $msg", @_); }

# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->set_config($mailsaobject->{conf});

  # the important bit!
  $self->register_eval_rule("check_fromname_spoof", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule("check_fromname_different", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule("check_fromname_domain_differ", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule("check_fromname_contains_email", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule("check_fromname_equals_to", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule("check_fromname_owners_differ", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule("check_fromname_equals_replyto", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  return $self;
}

sub set_config {
  my ($self, $conf) = @_;
  my @cmds = ();

  push (@cmds, {
    setting => 'fns_add_addrlist',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_ADDRLIST,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      local($1,$2);
      if ($value !~ /^ \( (.+?) \) \s+ (.+) \z/sx) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      my $listname = "FNS_".lc($1);
      $self->{parser}->add_to_addrlist($listname, split(/\s+/, lc $2));
      $self->{fns_addrlists}{$listname} = 1;
    }
  });

  push (@cmds, {
    setting => 'fns_remove_addrlist',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_ADDRLIST,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      local($1,$2);
      if ($value !~ /^ \( (.+?) \) \s+ (.+) \z/sx) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      my $listname = "FNS_".lc($1);
      $self->{parser}->remove_from_addrlist($listname, split (/\s+/, lc $2));
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
      $self->{fns_ignore_dkim}->{$_} = 1 foreach (split(/\s+/, lc $value));
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
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value eq '') {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      if ($value !~ /^[012]$/) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      $self->{fns_check} = $value;
    }
  });

  $conf->{parser}->register_commands(\@cmds);
}

sub parsed_metadata {
  my ($self, $opts) = @_;
  my $pms = $opts->{permsgstatus};

  # If fns_ignore_dkim used, force wait for DKIM results
  if (%{$pms->{conf}->{fns_ignore_dkim}}) {
    if ($self->{main}->{local_tests_only}) {
      dbg("local tests only, ignoring fns_ignore_dkim setting");
    }
    # Check that DKIM module is loaded (a bit kludgy check)
    elsif (exists $pms->{conf}->{dkim_timeout}) {
      # Initialize async queue, any eval calls will queue their checks
      $pms->{fromname_async_queue} = [];
      # Process and finish queue as soon as DKIM is ready
      $pms->action_depends_on_tags('DKIMDOMAIN', sub {
        $self->_check_async_queue($pms);
      });
    } else {
      dbg("DKIM plugin not loaded, ignoring fns_ignore_dkim setting");
    }
  }
}

sub _check_eval {
  my ($self, $pms, $result) = @_;

  if (exists $pms->{fromname_async_queue}) {
    my $rulename = $pms->get_current_eval_rule_name();
    push @{$pms->{fromname_async_queue}}, sub {
      if ($result->()) {
        $pms->got_hit($rulename, '', ruletype => 'header');
      } else {
        $pms->rule_ready($rulename);
      }
    };
    return; # return undef for async status
  }

  $self->_check_fromnamespoof($pms);
  # make sure not to return undef, as this is not async anymore
  return $result->() || 0;
}

sub check_fromname_spoof {
  my ($self, $pms, $check_lvl) = @_;

  # Some deprecated eval parameter, was not documented?
  if (!defined $check_lvl || $check_lvl !~ /^[012]$/) {
    $check_lvl = $pms->{conf}->{fns_check};
  }

  my $result = sub {
    my @array = (
      ($pms->{fromname_address_different}),
      ($pms->{fromname_address_different} && $pms->{fromname_owner_different}),
      ($pms->{fromname_address_different} && $pms->{fromname_domain_different})
    );
    $array[$check_lvl];
  };

  return $self->_check_eval($pms, $result);
}

sub check_fromname_different {
  my ($self, $pms) = @_;

  my $result = sub {
    $pms->{fromname_address_different};
  };

  return $self->_check_eval($pms, $result);
}

sub check_fromname_domain_differ {
  my ($self, $pms) = @_;

  my $result = sub {
    $pms->{fromname_domain_different};
  };

  return $self->_check_eval($pms, $result);
}

sub check_fromname_contains_email {
  my ($self, $pms) = @_;

  my $result = sub {
    $pms->{fromname_contains_email};
  };

  return $self->_check_eval($pms, $result);
}

sub check_fromname_equals_to {
  my ($self, $pms) = @_;

  my $result = sub {
    $pms->{fromname_equals_to_addr};
  };

  return $self->_check_eval($pms, $result);
}

sub check_fromname_owners_differ {
  my ($self, $pms) = @_;

  my $result = sub {
    $pms->{fromname_owner_different};
  };

  return $self->_check_eval($pms, $result);
}

sub check_fromname_equals_replyto {
  my ($self, $pms) = @_;

  my $result = sub {
    $pms->{fromname_equals_replyto};
  };

  return $self->_check_eval($pms, $result);
}

sub check_cleanup {
  my ($self, $opts) = @_;

  $self->_check_async_queue($opts->{permsgstatus});
}

# Shall only be called when DKIMDOMAIN is ready, or from check_cleanup() to
# make sure _check_fromnamespoof is called if DKIMDOMAIN was never set
sub _check_async_queue {
  my ($self, $pms) = @_;

  if (exists $pms->{fromname_async_queue}) {
    $self->_check_fromnamespoof($pms);
    $_->() foreach (@{$pms->{fromname_async_queue}});
    # No more async queueing needed.  If any evals are called later, they
    # will act on the results directly.
    delete $pms->{fromname_async_queue};
  }
}

sub _check_fromnamespoof {
  my ($self, $pms) = @_;

  return if $pms->{fromname_checked};
  $pms->{fromname_checked} = 1;

  my $conf = $pms->{conf};

  foreach my $addr (split(/\s+/, $pms->get_tag('DKIMDOMAIN')||'')) {
    if ($conf->{fns_ignore_dkim}->{lc $addr}) {
      dbg("ignoring, DKIM signed: $addr");
      return;
    }
  }

  foreach my $iheader (keys %{$conf->{fns_ignore_header}}) {
    if ($pms->get($iheader)) {
      dbg("ignoring, header $iheader found");
      return;
    }
  }

  # Parse From addr
  my $from_addr = lc $pms->get('From:addr');
  my $from_domain = $self->{main}->{registryboundaries}->uri_to_domain("mailto:$from_addr");
  return unless defined $from_domain;

  # Parse From name
  my $fromname = lc $pms->get('From:name');
  # Very common to have From address cloned into name, ignore?
  #if ($fromname eq $from_addr) {
  #  dbg("ignoring, From-name is exactly same as From addr: $fromname");
  #  return;
  #}
  my ($fromname_addr, $fromname_domain);
  if ($fromname =~ /\b([\w\.\!\#\$\%\&\'\*\+\/\=\?\^\_\`\{\|\}\~-]+\@\w[\w-]*\.\w[\w.-]++)\b/i) {
    $fromname_addr = $1;
    $fromname_domain = $self->{main}->{registryboundaries}->uri_to_domain("mailto:$fromname_addr");
    # No valid domain/TLD found? Any reason to keep testing a possibly obfuscated one?
    if (!defined $fromname_domain) {
      dbg("no From-name addr found");
      return;
    }
    $pms->{fromname_contains_email} = 1; # check_fromname_contains_email hit
    # Calculate "closeness" (this really needs documentation, as it's hard to understand)
    my $nochar = ($fromname =~ y/a-z0-9//c);
    $nochar -= ($fromname_addr =~ y/a-z0-9//c);
    my $len = length($fromname) + $nochar - length($fromname_addr);
    unless ($len <= $conf->{fns_extrachars}) {
      dbg("not enough closeness for From-name/addr: $fromname <=> $fromname_addr ($len <= $conf->{fns_extrachars})");
      return;
    }
  } else {
    # No point continuing if email was not found inside name
    dbg("no From-name addr found");
    return;
  }

  # Parse owners
  my $list_refs = {};
  if ($conf->{fns_addrlists}) {
    my @lists = keys %{$conf->{fns_addrlists}};
    foreach my $list (@lists) {
      $list_refs->{$list} = $conf->{$list};
    }
    dbg("using addrlists for owner aliases: ".join(', ', map { s/^FNS_//r; } @lists));
  }
  my $fromname_owner = $self->_find_address_owner($fromname_addr, $fromname_domain, $list_refs);
  my $from_owner = $self->_find_address_owner($from_addr, $from_domain, $list_refs);

  dbg("Parsed From-name addr/domain/owner: $fromname_addr/$fromname_domain/$fromname_owner");
  dbg("Parsed From-addr addr/domain/owner: $from_addr/$from_domain/$from_owner");

  if ($fromname_addr ne $from_addr) {
    dbg("From-name addr differs from From addr: $fromname_addr != $from_addr");
    $pms->{fromname_address_different} = 1;
  }
  if ($fromname_domain ne $from_domain) {
    dbg("From-name domain differs from From domain: $fromname_domain != $from_domain");
    $pms->{fromname_domain_different} = 1;
  }
  if ($fromname_owner ne $from_owner) {
    dbg("From-name owner differs from From owner: $fromname_owner != $from_owner");
    $pms->{fromname_owner_different} = 1;
  }

  # Check Reply-To related
  my $replyto_addr = lc $pms->get('Reply-To:addr');
  if ($fromname_addr eq $replyto_addr) {
    dbg("From-name addr is same as Reply-To addr: $fromname_addr");
    $pms->{fromname_equals_replyto} = 1;
  }

  # Check To related
  foreach my $to_addr ($pms->all_to_addrs()) {
    if ($fromname_addr eq $to_addr) {
      dbg("From-name addr is same as To addr: $fromname_addr");
      $pms->{fromname_equals_to_addr} = 1;
      last;
    }
  }

  # Set tags
  if ($pms->{fromname_address_different} || $pms->{fromname_owner_different}) {
    $pms->set_tag("FNSFNAMEADDR", $fromname_addr);
    $pms->set_tag("FNSFNAMEDOMAIN", $fromname_domain);
    $pms->set_tag("FNSFNAMEOWNER", $fromname_owner);
    $pms->set_tag("FNSFADDRADDR", $from_addr);
    $pms->set_tag("FNSFADDRDOMAIN", $from_domain);
    $pms->set_tag("FNSFADDROWNER", $from_owner);
  }
}

sub _find_address_owner {
  my ($self, $addr, $addr_domain, $list_refs) = @_;

  # Check fns addrlist first for user defined mapping
  foreach my $owner (keys %{$list_refs}) {
    foreach my $listaddr (keys %{$list_refs->{$owner}}) {
      if ($addr =~ $list_refs->{$owner}{$listaddr}) {
        $owner =~ s/^FNS_//;
        return lc $owner;
      }
    }
  }

  # If we have subdomain addr foo.bar@sub.domain.com,
  # this will try to recheck foo.bar@domain.com from addrlist
  local($1,$2);
  if ($addr =~ /^([^\@]+)\@(.+)$/) {
    if ($2 ne $addr_domain) {
      return $self->_find_address_owner("$1\@$addr_domain", $addr_domain, $list_refs);
    }
  }

  # Grab the first component of TLD
  if ($addr_domain =~ /^([^.]+)\./) {
    return $1;
  } else {
    return $addr_domain;
  }
}

1;
