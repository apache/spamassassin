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

Mail::SpamAssassin::Plugin::AuthRes - use Authentication-Results header fields

=head1 SYNOPSIS

=head2 SpamAssassin configuration:

loadplugin     Mail::SpamAssassin::Plugin::AuthRes

authres_trusted_authserv  myserv.example.com
authres_networks  all

=head1 DESCRIPTION

This plugin parses Authentication-Results header fields and can supply the
results obtained to other plugins, so as to avoid repeating checks that have
been performed already.

=cut

package Mail::SpamAssassin::Plugin::AuthRes;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use strict;
use warnings;
# use bytes;
use re 'taint';

our @ISA = qw(Mail::SpamAssassin::Plugin);

# list of valid methods and values
# https://www.iana.org/assignments/email-auth/email-auth.xhtml
# some others not in that list:
#   dkim-atps=neutral
#   dmarc=bestguesspass  (some microsoft stuff)
my %method_result = (
  'arc' => {'fail'=>1,'none'=>1,'pass'=>1},
  'auth' => {'fail'=>1,'none'=>1,'pass'=>1,'permerror'=>1,'temperror'=>1},
  'dkim' => {'fail'=>1,'neutral'=>1,'none'=>1,'pass'=>1,'permerror'=>1,'policy'=>1,'temperror'=>1},
  'dkim-adsp' => {'discard'=>1,'fail'=>1,'none'=>1,'nxdomain'=>1,'pass'=>1,'permerror'=>1,'temperror'=>1,'unknown'=>1},
  'dkim-atps' => {'fail'=>1,'none'=>1,'pass'=>1,'permerror'=>1,'temperror'=>1,'neutral'=>1},
  'dmarc' => {'bestguesspass'=>1,'fail'=>1,'none'=>1,'pass'=>1,'permerror'=>1,'temperror'=>1},
  'dnswl' => {'none'=>1,'pass'=>1,'permerror'=>1,'temperror'=>1},
  'domainkeys' => {'fail'=>1,'neutral'=>1,'none'=>1,'permerror'=>1,'policy'=>1,'pass'=>1,'temperror'=>1},
  'iprev' => {'fail'=>1,'pass'=>1,'permerror'=>1,'temperror'=>1},
  'rrvs' => {'fail'=>1,'none'=>1,'pass'=>1,'permerror'=>1,'temperror'=>1,'unknown'=>1},
  'sender-id' => {'fail'=>1,'hardfail'=>1,'neutral'=>1,'none'=>1,'pass'=>1,'permerror'=>1,'policy'=>1,'softfail'=>1,'temperror'=>1},
  'smime' => {'fail'=>1,'neutral'=>1,'none'=>1,'pass'=>1,'permerror'=>1,'policy'=>1,'temperror'=>1},
  'spf' => {'fail'=>1,'hardfail'=>1,'neutral'=>1,'none'=>1,'pass'=>1,'permerror'=>1,'policy'=>1,'softfail'=>1,'temperror'=>1},
  'vbr' => {'fail'=>1,'none'=>1,'pass'=>1,'permerror'=>1,'temperror'=>1},
);
my %method_ptype_prop = (
  'arc' => {'smtp' => {'remote-ip'=>1}, 'header' => {'oldest-pass'=>1}, 'arc' => {'chain'=>1}},
  'auth' => {'smtp' => {'auth'=>1,'mailfrom'=>1}},
  'dkim' => {'header' => {'d'=>1,'i'=>1,'b'=>1,'a'=>1,'s'=>1}},
  'dkim-adsp' => {'header' => {'from'=>1}},
  'dkim-atps' => {'header' => {'from'=>1}},
  'dmarc' => {'header' => {'from'=>1}, 'policy' => {'dmarc'=>1}},
  'dnswl' => {'dns' => {'zone'=>1,'sec'=>1}, 'policy' => {'ip'=>1,'txt'=>1}},
  'domainkeys' => {'header' => {'d'=>1,'from'=>1,'sender'=>1}},
  'iprev' => {'policy' => {'iprev'=>1}},
  'rrvs' => {'smtp' => {'rcptto'=>1}},
  'sender-id' => {'header' => {'*'=>1}},
  'smime' => {'body' => {'smime-part'=>1,'smime-identifer'=>1,'smime-serial'=>1,'smime-issuer'=>1}},
  'spf' => {'smtp' => {'mailfrom'=>1,'mfrom'=>1,'helo'=>1,'rcpttodomain'=>1}},
  'vbr' => {'header' => {'md'=>1,'mv'=>1}},
);
      
# Some MIME helpers
my $QUOTED_STRING = qr/"((?:[^"\\]++|\\.)*+)"?/;
my $TOKEN = qr/[^\s\x00-\x1f\x80-\xff\(\)\<\>\@\,\;\:\/\[\]\?\=\"]+/;
my $ATOM = qr/[a-zA-Z0-9\@\!\#\$\%\&\\\'\*\+\-\/\=\?\^\_\`\{\|\}\~]+/;

sub new {
  my ($class, $mailsa) = @_;

  # the usual perlobj boilerplate to create a subclass object
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsa);
  bless ($self, $class);

  $self->set_config($mailsa->{conf});

  # process first as other plugins might depend on us
  $self->register_method_priority("parsed_metadata", -10);

  $self->register_eval_rule("check_authres_result", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);

  return $self;
}

sub set_config {
  my ($self, $conf) = @_;
  my @cmds;

=head1 ADMINISTRATOR SETTINGS

=over

=item authres_networks internal/trusted/all    (default: internal)

Process Authenticated-Results headers set by servers from these networks
(refers to SpamAssassin *_networks zones).  Any header outside this is
completely ignored (affects all module settings).

 internal   = internal_networks
 trusted    = internal_networks + trusted_networks
 all        = all above + all external

Setting "all" is safe only if your MX servers filter properly all incoming
A-R headers, and you use authres_trusted_authserv to match your authserv-id. 
This is suitable for default OpenDKIM for example.  These settings might
also be required if your filters do not insert A-R header to correct
position above the internal Received header (some known offenders: OpenDKIM,
OpenDMARC, amavisd-milter).

=back

=cut

  push (@cmds, {
    setting => 'authres_networks',
    is_admin => 1,
    default => 'internal',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if (!defined $value || $value =~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      $value = lc($value);
      if ($value =~ /^(?:internal|trusted|all)$/) {
        $self->{authres_networks} = $value;
      } else {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
    }
  });

=over

=item authres_trusted_authserv authservid1 id2 ...   (default: none)

Trusted authentication server IDs (the domain-name-like first word of
Authentication-Results field, also known as C<authserv-id>).

Note that if set, ALL A-R headers are ignored unless a match is found.

Use strongly recommended, possibly along with authres_networks all.

=back

=cut

  push (@cmds, {
    setting => 'authres_trusted_authserv',
    is_admin => 1,
    default => {},
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if (!defined $value || $value =~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      foreach my $id (split(/\s+/, lc $value)) {
        $self->{authres_trusted_authserv}->{$id} = 1;
      }
    }
  });

=over

=item authres_ignored_authserv authservid1 id2 ...   (default: none)

Ignored authentication server IDs (the domain-name-like first word of
Authentication-Results field, also known as C<authserv-id>).

Any A-R header is ignored if match is found.

=back

=cut

  push (@cmds, {
    setting => 'authres_ignored_authserv',
    is_admin => 1,
    default => {},
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if (!defined $value || $value =~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      foreach my $id (split(/\s+/, lc $value)) {
        $self->{authres_ignored_authserv}->{$id} = 1;
      }
    }
  });

  $conf->{parser}->register_commands(\@cmds);
}

=head1 METADATA

Parsed headers are stored in $pms-E<gt>{authres_parsed}, as a hash of array
of hashes where results are collected by method.  For example, the header
field:

  Authentication-Results: server.example.com;
    spf=pass smtp.mailfrom=bounce.example.org;
    dkim=pass header.i=@example.org;
    dkim=fail header.i=@another.signing.domain.example

Produces the following structure:

 $pms->{authres_parsed} = {
   'dkim' => [
     {
       'properties' => {
         'header' => {
           'i' => '@example.org'
         }
       },
       'authserv' => 'server.example.com',
       'result' => 'pass',
       'version' => 1,
       'reason' => ''
     },
     {
       'properties' => {
         'header' => {
           'i' => '@another.signing.domain.example'
         }
       },
       'result' => 'fail',
       'authserv' => 'server.example.com',
       'version' => 1,
       'reason' => ''
     },
   ],
 }

Within each array, the order of results is the original, which should be most
recent results first.

For checking result of methods, $pms-E<gt>{authres_result} is available:

 $pms->{authres_result} = {
   'dkim' => 'pass',
   'spf' => 'fail',
 }

=head1 EVAL FUNCTIONS

=over 4

=item header RULENAME eval:check_authres_result(method, result)

Can be used to check results.

Reference of valid result methods and values:
C<https://www.iana.org/assignments/email-auth/email-auth.xhtml>

Additionally the result value of 'missing' can be used to check if there is
no result at all.

  ifplugin Mail::SpamAssassin::Plugin::AuthRes
  ifplugin !(Mail::SpamAssassin::Plugin::SPF)
    header  SPF_PASS      eval:check_authres_result('spf', 'pass')
    header  SPF_FAIL      eval:check_authres_result('spf', 'fail')
    header  SPF_SOFTFAIL  eval:check_authres_result('spf', 'softfail')
    header  SPF_TEMPFAIL  eval:check_authres_result('spf', 'tempfail')
  endif
  ifplugin !(Mail::SpamAssassin::Plugin::DKIM)
    header  DKIM_VERIFIED  eval:check_authres_result('dkim', 'pass')
    header  DKIM_INVALID   eval:check_authres_result('dkim', 'fail')
  endif
  endif

=back

=cut

sub check_authres_result {
  my ($self, $pms, $method, $wanted_result) = @_;

  my $result = $pms->{authres_result}->{$method};
  $wanted_result = lc($wanted_result);

  if ($wanted_result eq 'missing') {
    return !defined($result) ? 1 : 0;
  }

  return 0 unless defined $result;
  return ($wanted_result eq $result) ? 1 : 0;
}

sub parsed_metadata {
  my ($self, $opts) = @_;

  my $pms = $opts->{permsgstatus};

  my @authres;
  my $nethdr;

  if ($pms->{conf}->{authres_networks} eq 'internal') {
    $nethdr = 'ALL-INTERNAL';
  } elsif ($pms->{conf}->{authres_networks} eq 'trusted') {
    $nethdr = 'ALL-TRUSTED';
  } else {
    $nethdr = 'ALL';
  }

  foreach my $hdr (split(/^/m, $pms->get($nethdr))) {
    if ($hdr =~ /^((?:Arc\-)?Authentication-Results):\s*(.+)/i) {
      push @authres, [$1,$2];
    }
  }

  if (!@authres) {
    dbg("authres: no Authentication-Results headers found from %s",
      $pms->{conf}->{authres_networks});
    return 0;
  }

  foreach (@authres) {
    eval {
      $self->parse_authres($pms, $_->[0], $_->[1]);
    } or do {
      dbg("authres: skipping header, $@");
    }
  }

  $pms->{authres_result} = {};
  # Set $pms->{authres_result} info for all found methods
  # 'pass' will always win if multiple results
  foreach my $method (keys %method_result) {
    my $parsed = $pms->{authres_parsed}->{$method};
    next if !$parsed;
    foreach my $pref (@$parsed) {
      if (!$pms->{authres_result}->{$method} ||
            $pref->{result} eq 'pass')
      {
        $pms->{authres_result}->{$method} = $pref->{result};
      }
    }
  }

  if (%{$pms->{authres_result}}) {
    dbg("authres: results: %s",
      join(' ', map { $_.'='.$pms->{authres_result}->{$_} }
        sort keys %{$pms->{authres_result}}));
  } else {
    dbg("authres: no results");
  }
}

sub parse_authres {
  my ($self, $pms, $hdrname, $hdr) = @_;

  dbg("authres: parsing $hdrname: $hdr");

  my $authserv;
  my $version = 1;
  my @methods;
  my $arc_index;

  local $_ = $hdr;

  if ($hdrname =~ /^ARC-/i) {
    if (!/\Gi\b/gcs) {
      die("missing arc index: $hdr");
    }
    skip_cfws();
    if (!/\G=/gcs) {
      die("invalid arc index: ".substr($_, pos())."\n");
    }
    skip_cfws();
    if (!/\G(\d+)/gcs) {
      die("invalid arc index: ".substr($_, pos())."\n");
    }
    $arc_index = $1;
    if ($arc_index < 1 || $arc_index > 50) {
      die("invalid arc index: $arc_index\n");
    }
    skip_cfws();
    if (!/\G;/gcs) {
      die("missing delimiter: ".substr($_, pos())."\n");
    }
    skip_cfws();
  }

  # authserv-id
  if (!/\G($TOKEN)/gcs) {
    die("invalid authserv: ".substr($_, pos())."\n");
  }
  $authserv = lc($1);

  # some invalid headers start with spf=foo etc, missing authserv-id
  if (/\G=/gcs) {
    die("missing authserv: $hdr\n");
  }

  if (%{$pms->{conf}->{authres_trusted_authserv}}) {
    if (!$pms->{conf}->{authres_trusted_authserv}->{$authserv}) {
      die("authserv not trusted: $authserv\n");
    }
  }
  if ($pms->{conf}->{authres_ignored_authserv}->{$authserv}) {
    die("ignored authserv: $authserv\n");
  }

  # skip authserv version
  skip_cfws();
  if (/\G\d+/gcs) {
    skip_cfws();
  }

  if (!/\G;/gcs) {
    die("missing delimiter: ".substr($_, pos())."\n");
  }
  skip_cfws();

  while (pos() < length()) {
    my ($method, $result);
    my $reason = '';
    my $props = {};

    # some silly generators add duplicate authserv-id; here
    if (/\G\Q${authserv}\E\s*;/gcs) {
      skip_cfws();
    }

    # skip none method
    if (/\Gnone\b/igcs) {
      die("method none\n");
    }

    # method / version = result
    if (!/\G([\w-]+)/gcs) {
      die("invalid method: ".substr($_, pos())."\n");
    }
    $method = lc($1);
    if (!exists $method_result{$method}) {
      die("unknown method: $method: $hdr\n");
    }
    skip_cfws();
    if (/\G\//gcs) {
      skip_cfws();
      if (!/\G\d+/gcs) {
        die("invalid $method version: ".substr($_, pos())."\n");
      }
      $version = $1;
      skip_cfws();
    }
    if (!/\G=/gcs) {
      die("missing result for $method: ".substr($_, pos())."\n");
    }
    skip_cfws();
    if (!/\G(\w+)/gcs) {
      die("invalid result for $method: ".substr($_, pos())."\n");
    }
    $result = $1;
    if (!exists $method_result{$method}{$result}) {
      die("unknown result for $method: $result\n");
    }
    skip_cfws();

    # reason = value
    if (/\Greason\b/igcs) {
      skip_cfws();
      if (!/\G=/gcs) {
        die("invalid reason: ".substr($_, pos())."\n");
      }
      skip_cfws();
      if (!/\G$QUOTED_STRING|($TOKEN)/gcs) {
        die("invalid reason: ".substr($_, pos())."\n");
      }
      $reason = defined $1 ? $1 : $2;
      skip_cfws();
    }

    # action = value (some microsoft ARC stuff?)
    if (/\Gaction\b/igcs) {
      skip_cfws();
      if (!/\G=/gcs) {
        die("invalid action: ".substr($_, pos())."\n");
      }
      skip_cfws();
      if (!/\G$QUOTED_STRING|$TOKEN/gcs) {
        die("invalid action: ".substr($_, pos())."\n");
      }
      skip_cfws();
    }

    # ptype.property = value
    while (pos() < length()) {
      my ($ptype, $property, $value);

      # no props?
      if (/\G(?:;|$)/gcs) {
        skip_cfws();
        last;
      }

      # ptype
      if (!/\G([\w-]+)/gcs) {
        die("invalid ptype: ".substr($_,pos())."\n");
      }
      $ptype = lc($1);
      if (!exists $method_ptype_prop{$method}{$ptype}) {
        die("unknown ptype: $method/$ptype\n");
      }
      skip_cfws();

      # dot
      if (!/\G\./gcs) {
        die("missing property: ".substr($_, pos())."\n");
      }
      skip_cfws();

      # property
      if (!/\G([\w-]+)/gcs) {
        die("invalid property: ".substr($_, pos())."\n");
      }
      $property = lc($1);
      if (!exists $method_ptype_prop{$method}{$ptype}{$property} &&
          !exists $method_ptype_prop{$method}{$ptype}{'*'}) {
        die("unknown property for $method/$ptype: $property\n");
      }
      skip_cfws();

      # =
      if (!/\G=/gcs) {
        die("missing property value: ".substr($_, pos())."\n");
      }
      skip_cfws();

      # value:
      # The grammar is ( value / [ [ local-part ] "@" ] domain-name )
      # where value := token / quoted-string
      # and local-part := dot-atom / quoted-string / obs-local-part
      if (!/\G$QUOTED_STRING|($ATOM(?:\.$ATOM)*|$TOKEN)(?=(?:[\s;]|$))/gcs) {
        die("invalid $method/$ptype.$property value: ".substr($_, pos())."\n");
      }
      $value = defined $1 ? $1 : $2;
      skip_cfws();

      $props->{$ptype}->{$property} = $value;

      if (/\G(?:;|$)/gcs) {
        skip_cfws();
        last;
      }
    }

    push @methods, [$method, {
        'authserv' => $authserv,
        'version' => $version,
        'result' => $result,
        'reason' => $reason,
        'properties' => $props,
        'arc_index' => $arc_index,
        }];
  }

  # paranoid check..
  if (pos() < length()) {
    die("parse ended prematurely? ".substr($_, pos())."\n");
  }

  # Pushed to pms only if header parsed completely
  foreach my $marr (@methods) {
    push @{$pms->{authres_parsed}->{$marr->[0]}}, $marr->[1];
  }

  return 1;
}

# skip whitespace and comments
sub skip_cfws {
  /\G\s*/gcs;
  if (/\G\(/gcs) {
    my $i = 1;
    while (/\G.*?([()]|\z)/gcs) {
      $1 eq ')' ? $i-- : $i++;
      last if !$i;
    }
    die("comment not ended\n") if $i;
    /\G\s*/gcs;
  }
}

#sub check_cleanup {
#  my ($self, $opts) = @_;
#  my $pms = $opts->{permsgstatus};
#  use Data::Dumper;
#  print STDERR Dumper($pms->{authres_parsed});
#  print STDERR Dumper($pms->{authres_result});
#}

1;
