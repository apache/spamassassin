# <@LICENSE>
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to you under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at:
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# </@LICENSE>

=head1 NAME

HashBL - query hashed (and unhashed) DNS blocklists

=head1 SYNOPSIS

  loadplugin Mail::SpamAssassin::Plugin::HashBL

  # NON-WORKING usage examples below, replace xxx.example.invalid with real list
  # See documentation below for detailed usage

  header   HASHBL_EMAIL eval:check_hashbl_emails('ebl.example.invalid')
  describe HASHBL_EMAIL Message contains email address found on EBL
  tflags   HASHBL_EMAIL net

  hashbl_acl_freemail gmail.com
  header   HASHBL_OSENDR eval:check_hashbl_emails('rbl.example.invalid/A', 'md5/max=10/shuffle', 'X-Original-Sender', '^127\.', 'freemail')
  describe HASHBL_OSENDR Message contains email address found on HASHBL
  tflags   HASHBL_OSENDR net

  body     HASHBL_BTC eval:check_hashbl_bodyre('btcbl.example.invalid', 'sha1/max=10/shuffle', '\b([13][a-km-zA-HJ-NP-Z1-9]{25,34})\b')
  describe HASHBL_BTC Message contains BTC address found on BTCBL
  tflags   HASHBL_BTC net

  header   HASHBL_URI eval:check_hashbl_uris('rbl.example.invalid', 'sha1', '127.0.0.32')
  describe HASHBL_URI Message contains uri found on rbl
  tflags   HASHBL_URI net

  # Capture tag using SA 4.0 regex named capture feature
  header   __X_SOME_ID X-Some-ID =~ /^(?<XSOMEID>\d{10,20})$/
  # Query the tag value as is from a DNSBL
  header   HASHBL_TAG eval:check_hashbl_tag('idbl.example.invalid/A', 'raw', 'XSOMEID', '^127\.')

=head1 DESCRIPTION

This plugin support multiple types of hashed or unhashed DNS blocklists.

OPTS refers to multiple generic options:

  raw      do not hash data, query as is
  md5      hash query with MD5
  sha1     hash query with SHA1
  case     keep case before hashing, default is to lowercase
  max=x	   maximum number of queries
  shuffle  if max exceeded, random shuffle queries before truncating to limit

Multiple options can be separated with slash or other non-word character.
If OPTS is empty ('') or missing, default is used.

HEADERS refers to slash separated list of Headers to process:

  ALL           all headers
  ALLFROM       all From headers as returned by $pms->all_from_addrs()
  EnvelopeFrom  message envelope from (Return-Path etc)
  HeaderName    any header as used with $pms->get()

if HEADERS is empty ('') or missing, default is used.

=over 4

=item header RULE check_hashbl_emails('bl.example.invalid/A', 'OPTS', 'HEADERS/body', '^127\.')

Check email addresses from DNS list, "body" can be specified along with
headers to search body for emails.  Optional subtest regexp to match DNS
answer.  Note that eval rule type must always be "header".

DNS query type can be appended to list with /A (default) or /TXT.

Additional supported OPTS:

  nodot    strip username dots from email
  notag    strip username tags from email
  nouri    ignore emails inside uris
  noquote  ignore emails inside < > or possible quotings

Default OPTS: sha1/notag/noquote/max=10/shuffle

Default HEADERS: ALLFROM/Reply-To/body

For existing public email blocklist, see: http://msbl.org/ebl.html

  # Working example, see http://msbl.org/ebl.html before usage
  header   HASHBL_EMAIL eval:check_hashbl_emails('ebl.msbl.org')
  describe HASHBL_EMAIL Message contains email address found on EBL
  tflags   HASHBL_EMAIL net

Default regex for matching and capturing emails can be overridden with
C<hashbl_email_regex>.  Likewise, the default welcomelist can be changed with
C<hashbl_email_welcomelist>.  Only change if you know what you are doing, see
module source for the defaults.  Example: hashbl_email_regex \S+@\S+.com

=back

=over 4

=item header RULE check_hashbl_uris('bl.example.invalid/A', 'OPTS', '^127\.')

Check uris from DNS list, optional subtest regexp to match DNS
answer.

DNS query type can be appended to list with /A (default) or /TXT.

Default OPTS: sha1/max=10/shuffle

=back

=over 4

=item body RULE check_hashbl_bodyre('bl.example.invalid/A', 'OPTS', '\b(match)\b', '^127\.')

Search body for matching regexp and query the string captured.  Regexp must
have a single capture ( ) for the string ($1).  Optional subtest regexp to
match DNS answer.  Note that eval rule type must be "body" or "rawbody".

=back

=over 4

=item header RULE check_hashbl_tag('bl.example.invalid/A', 'OPTS', 'TAGNAME', '^127\.')

Lookup value of SpamAssassin tag _TAGNAME_ from DNS list, optional subtest
regexp to match DNS answer.

DNS query type can be appended to list with /A (default) or /TXT.

Default OPTS: sha1/max=10/shuffle

Additional supported OPTS:

  ip        only query if value is valid IPv4/IPv6 address
  ipv4      only query if value is valid IPv4 address
  ipv6      only query if value is valid IPv6 address
  revip     reverse IP before query
  fqdn      only query if value is valid FQDN (is_fqdn_valid)
  tld       only query if value has valid TLD (is_domain_valid)
  trim      trim name from hostname to domain (trim_domain)

If both ip/ipv4/ipv6 and fqdn/tld are enabled, only either of them is
required to match.  Both fqdn and tld are needed for complete FQDN+TLD
check.

=back

=cut

package Mail::SpamAssassin::Plugin::HashBL;
use strict;
use warnings;
use re 'taint';

my $VERSION = 0.101;

use Digest::MD5 qw(md5_hex);
use Digest::SHA qw(sha1_hex);

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Constants qw(:ip);
use Mail::SpamAssassin::Util qw(compile_regexp is_fqdn_valid reverse_ip_address);

our @ISA = qw(Mail::SpamAssassin::Plugin);

sub dbg { my $msg = shift; Mail::SpamAssassin::Plugin::dbg("HashBL: $msg", @_); }

sub new {
  my ($class, $mailsa) = @_;

  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsa);
  bless ($self, $class);

  # are network tests enabled?
  if ($mailsa->{local_tests_only}) {
    $self->{hashbl_available} = 0;
    dbg("local tests only, disabling HashBL");
  } else {
    $self->{hashbl_available} = 1;
  }

  $self->{evalfuncs} = {
    'check_hashbl_emails' => $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS,
    'check_hashbl_uris' => $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS,
    'check_hashbl_bodyre' => $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS,
    'check_hashbl_tag' => $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS,
  };
  while (my ($func, $type) = each %{$self->{evalfuncs}}) {
    $self->register_eval_rule($func, $type);
  }
  $self->set_config($mailsa->{conf});

  return $self;
}

sub set_config {
  my($self, $conf) = @_;
  my @cmds;

  push (@cmds, {
    setting => 'hashbl_ignore',
    is_admin => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
    default => {},
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if (!defined $value || $value eq '') {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      foreach my $str (split (/\s+/, $value)) {
        $self->{hashbl_ignore}->{lc $str} = 1;
      }
    }
  });

  push (@cmds, {
    setting => 'hashbl_email_regex',
    is_admin => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    # Some regexp tips courtesy of http://www.regular-expressions.info/email.html
    # full email regex v0.02
    default => qr/(?i)
      (?=.{0,64}\@)				# limit userpart to 64 chars (and speed up searching?)
      (?<![a-z0-9!#\$%&'*+\/=?^_`{|}~-])	# start boundary
      (						# capture email
      [a-z0-9!#\$%&'*+\/=?^_`{|}~-]+		# no dot in beginning
      (?:\.[a-z0-9!#\$%&'*+\/=?^_`{|}~-]+)*	# no consecutive dots, no ending dot
      \@
      (?:[a-z0-9](?:[a-z0-9-]{0,59}[a-z0-9])?\.){1,4} # max 4x61 char parts (should be enough?)
      _TLDS_ # ends with valid tld, _TLDS_ is template which will be replaced in finish_parsing_end()
      )
    /x,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if (!defined $value || $value eq '') {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      my ($rec, $err) = compile_regexp($value, 0);
      if (!$rec) {
        dbg("config: invalid hashbl_email_regex '$value': $err");
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      $self->{hashbl_email_regex} = $rec;
    }
  });

  push (@cmds, {
    setting => 'hashbl_email_welcomelist',
    aliases => ['hashbl_email_whitelist'], # removed in 4.1
    is_admin => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    default => qr/(?i)
      ^(?:
          abuse|support|sales|info|helpdesk|contact|kontakt
        | (?:post|host|domain)master
        | undisclosed.*                     # yahoo.com etc(?)
        | request-[a-f0-9]{16}              # live.com
        | bounced?-                         # yahoo.com etc
        | [a-f0-9]{8}(?:\.[a-f0-9]{8}|-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}) # gmail msgids?
        | .+=.+=.+                          # gmail forward
      )\@
    /x,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if (!defined $value || $value eq '') {
      }
      my ($rec, $err) = compile_regexp($value, 0);
      if (!$rec) {
        dbg("config: invalid hashbl_email_welcomelist '$value': $err");
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      $self->{hashbl_email_welcomelist} = $rec;
    }
  });

  $conf->{parser}->register_commands(\@cmds);
}

sub parse_config {
  my ($self, $opt) = @_;

  if ($opt->{key} =~ /^hashbl_acl_([a-z0-9]{1,32})$/i) {
    $self->inhibit_further_callbacks();
    return 1 unless $self->{hashbl_available};

    my $acl = lc($1);
    my @opts = split(/\s+/, $opt->{value});
    foreach my $tmp (@opts) {
      if ($tmp =~ /^(\!)?(\S+)$/i) {
        my $neg = $1;
        my $value = lc($2);
        if (defined $neg) {
          $self->{hashbl_acl}{$acl}{$value} = 0;
        } else {
          next if $acl eq 'all';
          # exclusions overrides
          if (!defined $self->{hashbl_acl}{$acl}{$value}) {
            $self->{hashbl_acl}{$acl}{$value} = 1
          }
        }
      } else {
        warn("invalid acl: $tmp");
      }
    }
    return 1;
  }

  return 0;
}

sub finish_parsing_start {
  my ($self, $opts) = @_;
  my $conf = $opts->{conf};

  # Adjust priority -100 to launch early
  # Find rulenames from eval_to_rule mappings
  foreach my $evalfunc (%{$self->{evalfuncs}}) {
    foreach (@{$conf->{eval_to_rule}->{$evalfunc}||[]}) {
      dbg("adjusting rule $_ priority to -100");
      $conf->{priority}->{$_} = -100;
    }
  }
}

sub finish_parsing_end {
  my ($self, $opts) = @_;

  return 0 if !$self->{hashbl_available};

  # valid_tlds_re will be available at finish_parsing_end, compile it now,
  # we only need to do it once and before possible forking
  # replace _TLDS_ with valid list of TLDs
  $opts->{conf}->{hashbl_email_regex} =~ s/_TLDS_/$self->{main}->{registryboundaries}->{valid_tlds_re}/g;
  #dbg("hashbl_email_regex: $opts->{conf}->{hashbl_email_regex}");
  $opts->{conf}->{hashbl_email_welcomelist} =~ s/_TLDS_/$self->{main}->{registryboundaries}->{valid_tlds_re}/g;
  #dbg("hashbl_email_welcomelist: $opts->{conf}->{hashbl_email_regex}");

  return 0;
}

sub _parse_opts {
  my %opts;
  foreach my $o (split(/\s*\/\s*/, lc $_[0])) {
    my ($k, $v) = split(/=/, $o);
    $opts{$k} = defined $v ? $v : 1;
  }
  return \%opts;
}

sub _get_emails {
  my ($self, $pms, $opts, $from, $acl) = @_;

  my @emails; # keep find order
  my %seen;

  foreach my $hdr (split(/\s*\/\s*/, $from)) {
    my $parsed_emails = $self->_parse_emails($pms, $opts, $hdr);
    foreach (@$parsed_emails) {
      next if $seen{$_}++;
      my ($domain) = ($_ =~ /.*\@(.+)/);
      if (defined $domain && defined $acl && $acl ne 'all') {
        if ($self->{hashbl_acl}{$acl}{$domain}) {
          push @emails, $_;
        }
      } else {
        push @emails, $_;
      }
    }
  }

  return \@emails;
}

sub _parse_emails {
  my ($self, $pms, $opts, $hdr) = @_;

  if (exists $pms->{hashbl_email_cache}{$hdr}) {
    return $pms->{hashbl_email_cache}{$hdr};
  }

  if ($hdr eq 'ALLFROM') {
    my @emails = $pms->all_from_addrs();
    return $pms->{hashbl_email_cache}{$hdr} = \@emails;
  }

  if (!defined $pms->{hashbl_welcomelist}) {
    %{$pms->{hashbl_welcomelist}} = map { lc($_) => 1 }
        ( $pms->get("X-Original-To:addr"),
          $pms->get("Apparently-To:addr"),
          $pms->get("Delivered-To:addr"),
          $pms->get("Envelope-To:addr"),
        );
    delete $pms->{hashbl_welcomelist}{''};
  }

  my $str = '';
  if ($hdr eq 'ALL') {
    $str = join("\n", $pms->get('ALL'));
  } elsif ($hdr eq 'body') {
    # get all <a href="mailto:", since they don't show up on stripped_body
    my $uris = $pms->get_uri_detail_list();
    while (my($uri, $info) = each %{$uris}) {
      if (defined $info->{types}->{a} && !defined $info->{types}->{parsed}) {
        if ($uri =~ /^mailto:(.+)/i) {
          $str .= "$1\n";
        }
      }
    }
    my $body = join('', @{$pms->get_decoded_stripped_body_text_array()});
    if ($opts->{nouri}) {
      # strip urls with possible emails inside
      $body =~ s#<?https?://\S{0,255}(?:\@|%40)\S{0,255}# #gi;
    }
    if ($opts->{noquote}) {
      # strip emails contained in <>, not mailto:
      # also strip ones followed by quote-like "wrote:" (but not fax: and tel: etc)
      $body =~ s#<?(?<!mailto:)$pms->{conf}->{hashbl_email_regex}(?:>|\s{1,10}(?!(?:fa(?:x|csi)|tel|phone|e?-?mail))[a-z]{2,11}:)# #gi;
    }
    $str .= $body;
  } else {
    $str .= join("\n", $pms->get($hdr));
  }

  my @emails; # keep find order
  my %seen;

  while ($str =~ /($pms->{conf}->{hashbl_email_regex})/g) {
    next if $seen{$1}++;
    push @emails, $1;
  }

  return $pms->{hashbl_email_cache}{$hdr} = \@emails;
}

sub check_hashbl_emails {
  my ($self, $pms, $list, $opts, $from, $subtest, $acl) = @_;

  return 0 if !$self->{hashbl_available};
  return 0 if !$pms->is_dns_available();

  my $rulename = $pms->get_current_eval_rule_name();

  if (!defined $list) {
    warn "HashBL: $rulename blocklist argument missing\n";
    return 0;
  }

  if ($subtest) {
    my ($rec, $err) = compile_regexp($subtest, 0);
    if (!$rec) {
      warn "HashBL: $rulename invalid subtest regex: $@\n";
      return 0;
    }
    $subtest = $rec;
  }

  # Parse opts, defaults
  $opts = _parse_opts($opts || 'sha1/notag/noquote/max=10/shuffle');
  $from = 'ALLFROM/Reply-To/body' if !$from;

  # Find all emails
  my $emails = $self->_get_emails($pms, $opts, $from, $acl);
  if (!@$emails) {
    if (defined $acl) {
      dbg("$rulename: no emails found ($from) on acl $acl");
    } else {
      dbg("$rulename: no emails found ($from)");
    }
    return 0;
  } else {
    dbg("$rulename: raw emails found: ".join(', ', @$emails));
  }

  # Filter list
  my @filtered_emails; # keep order
  my %seen;
  foreach my $email (@$emails) {
    next if $seen{$email}++;
    next if index($email, '@') == -1;
    if ($email =~ $pms->{conf}->{hashbl_email_welcomelist}
        || defined $pms->{hashbl_welcomelist}{$email}) {
      dbg("Address welcomelisted: $email");
      next;
    }
    if ($opts->{nodot} || $opts->{notag}) {
      my ($username, $domain) = ($email =~ /(.*)(\@.*)/);
      $username =~ tr/.//d if $opts->{nodot};
      $username =~ s/\+.*// if $opts->{notag};
      $email = $username.$domain;
    }
    push @filtered_emails, $opts->{case} ? $email : lc($email);
  }

  return 0 unless @filtered_emails;

  # Randomize order
  if ($opts->{shuffle}) {
    Mail::SpamAssassin::Util::fisher_yates_shuffle(\@filtered_emails);
  }

  # Truncate list
  my $max = $opts->{max} || 10;
  $#filtered_emails = $max-1 if scalar @filtered_emails > $max;

  $pms->rule_pending($rulename); # mark async

  foreach my $email (@filtered_emails) {
    $self->_submit_query($pms, $rulename, $email, $list, $opts, $subtest);
  }

  return 0;
}

sub check_hashbl_uris {
  my ($self, $pms, $list, $opts, $subtest) = @_;

  return 0 if !$self->{hashbl_available};
  return 0 if !$pms->is_dns_available();

  my $rulename = $pms->get_current_eval_rule_name();

  if (!defined $list) {
    warn "HashBL: $rulename blocklist argument missing\n";
    return 0;
  }

  if ($subtest) {
    my ($rec, $err) = compile_regexp($subtest, 0);
    if (!$rec) {
      warn "HashBL: $rulename invalid subtest regex: $@\n";
      return 0;
    }
    $subtest = $rec;
  }

  # Parse opts, defaults
  $opts = _parse_opts($opts || 'sha1/max=10/shuffle');

  if ($opts->{raw}) {
    warn "HashBL: $rulename raw option invalid\n";
    return 0;
  }

  my $uris = $pms->get_uri_detail_list();
  my %seen;
  my @filtered_uris;

  while (my($uri, $info) = each %{$uris}) {
    # we want to skip mailto: uris
    next if ($uri =~ /^mailto:/i);
    next if $seen{$uri}++;

    # no hosts/domains were found via this uri, so skip
    next unless $info->{hosts};
    next unless $info->{cleaned};
    next unless $info->{types}->{a} || $info->{types}->{parsed};
    foreach my $uri (@{$info->{cleaned}}) {
      # check url
      push @filtered_uris, $opts->{case} ? $uri : lc($uri);
    }
  }

  return 0 unless @filtered_uris;

  # Randomize order
  if ($opts->{shuffle}) {
    Mail::SpamAssassin::Util::fisher_yates_shuffle(\@filtered_uris);
  }

  # Truncate list
  my $max = $opts->{max} || 10;
  $#filtered_uris = $max-1 if scalar @filtered_uris > $max;

  $pms->rule_pending($rulename); # mark async

  foreach my $furi (@filtered_uris) {
    $self->_submit_query($pms, $rulename, $furi, $list, $opts, $subtest);
  }

  return 0;
}

sub check_hashbl_bodyre {
  my ($self, $pms, $bodyref, $list, $opts, $re, $subtest) = @_;

  return 0 if !$self->{hashbl_available};
  return 0 if !$pms->is_dns_available();

  my $rulename = $pms->get_current_eval_rule_name();

  if (!defined $list) {
    warn "HashBL: $rulename blocklist argument missing\n";
    return 0;
  }

  if (!$re) {
    warn "HashBL: $rulename missing body regex\n";
    return 0;
  }
  my ($rec, $err) = compile_regexp($re, 0);
  if (!$rec) {
    warn "HashBL: $rulename invalid body regex: $@\n";
    return 0;
  }
  $re = $rec;

  if ($subtest) {
    my ($rec, $err) = compile_regexp($subtest, 0);
    if (!$rec) {
      warn "HashBL: $rulename invalid subtest regex: $@\n";
      return 0;
    }
    $subtest = $rec;
  }

  # Parse opts, defaults
  $opts = _parse_opts($opts || 'sha1/max=10/shuffle');

  # Search body
  my @matches;
  my %seen;

  if (ref($bodyref) eq 'ARRAY') {
    # body, rawbody
    foreach my $body (@$bodyref) {
      while ($body =~ /$re/gs) {
        next if !defined $1;
        my $match = $opts->{case} ? $1 : lc($1);
        next if $seen{$match}++;
        push @matches, $match;
      }
    }
  } else {
    # full
    while ($$bodyref =~ /$re/gs) {
      next if !defined $1;
      my $match = $opts->{case} ? $1 : lc($1);
      next if $seen{$match}++;
      push @matches, $match;
    }
  }

  if (!@matches) {
    dbg("$rulename: no matches found");
    return 0;
  } else {
    dbg("$rulename: matches found: '".join("', '", @matches)."'");
  }

  # Randomize order
  if ($opts->{shuffle}) {
    Mail::SpamAssassin::Util::fisher_yates_shuffle(\@matches);
  }

  # Truncate list
  my $max = $opts->{max} || 10;
  $#matches = $max-1 if scalar @matches > $max;

  $pms->rule_pending($rulename); # mark async

  foreach my $match (@matches) {
    $self->_submit_query($pms, $rulename, $match, $list, $opts, $subtest);
  }

  return 0;
}

sub check_hashbl_tag {
  my ($self, $pms, $list, $opts, $tag, $subtest) = @_;

  return 0 if !$self->{hashbl_available};
  return 0 if !$pms->is_dns_available();

  my $rulename = $pms->get_current_eval_rule_name();

  if (!defined $list) {
    warn "HashBL: $rulename blocklist argument missing\n";
    return 0;
  }

  if (!defined $tag || $tag eq '') {
    warn "HashBL: $rulename tag argument missing\n";
    return 0;
  }

  if ($subtest) {
    my ($rec, $err) = compile_regexp($subtest, 0);
    if (!$rec) {
      warn "HashBL: $rulename invalid subtest regex: $@\n";
      return 0;
    }
    $subtest = $rec;
  }

  # Parse opts, defaults
  $opts = _parse_opts($opts || 'sha1/max=10/shuffle');
  $opts->{fqdn} = $opts->{tld} = 1  if $opts->{trim};

  # Strip possible _ delimiters
  $tag =~ s/^_(.+)_$/$1/;

  # Force uppercase
  $tag = uc($tag);

  $pms->rule_pending($rulename); # mark async

  $pms->action_depends_on_tags($tag, sub {
    $self->_check_hashbl_tag($pms, $list, $opts, $tag, $subtest, $rulename);
  });

  return 0;
}

sub _check_hashbl_tag {
  my ($self, $pms, $list, $opts, $tag, $subtest, $rulename) = @_;

  # Get raw array of tag values, get_tag() returns joined string
  my $valref = $pms->get_tag_raw($tag);
  my @vals = ref $valref ? @$valref : $valref;

  # Lowercase
  @vals = map { lc } @vals  if !$opts->{case};

  # Options
  foreach my $value (@vals) {
    my $is_ip = $value =~ IS_IP_ADDRESS;
    if ($opts->{ip}) {
      if (!$is_ip) {
        $value = undef;
        next;
      }
    }
    if ($opts->{ipv4}) {
      if ($value =~ IS_IPV4_ADDRESS) {
        $is_ip = 1;
      } else {
        $value = undef;
        next;
      }
    }
    if ($opts->{ipv6}) {
      if (!$is_ip || $value =~ IS_IPV4_ADDRESS) {
        $value = undef;
        next;
      }
    }
    if ($is_ip && $opts->{revip}) {
      $value = reverse_ip_address($value);
    }
    if (!$is_ip) {
      if ($opts->{fqdn} && !is_fqdn_valid($value)) {
        $value = undef;
        next;
      }
      if ($opts->{tld} && !$pms->{main}->{registryboundaries}->is_domain_valid($value)) {
        $value = undef;
        next;
      }
      if ($opts->{trim}) {
        $value = $pms->{main}->{registryboundaries}->trim_domain($value);
      }
    }
  }

  # Unique (and remove empty)
  @vals = do { my %seen; grep { defined $_ && !$seen{$_}++ } @vals; };

  if (!@vals) {
    $pms->rule_ready($rulename); # mark rule ready for metas
    return;
  }

  # Randomize order
  if ($opts->{shuffle}) {
    Mail::SpamAssassin::Util::fisher_yates_shuffle(\@vals);
  }

  # Truncate list
  my $max = $opts->{max} || 10;
  $#vals = $max-1 if scalar @vals > $max;

  foreach my $value (@vals) {
    $self->_submit_query($pms, $rulename, $value, $list, $opts, $subtest);
  }

  return;
}

sub _hash {
  my ($self, $opts, $value) = @_;

  if ($opts->{sha1}) {
    utf8::encode($value) if utf8::is_utf8($value); # sha1_hex expects bytes
    return sha1_hex($value);
  } elsif ($opts->{md5}) {
    utf8::encode($value) if utf8::is_utf8($value); # md5_hex expects bytes
    return md5_hex($value);
  } else {
    return $value;
  }
}

sub _submit_query {
  my ($self, $pms, $rulename, $value, $list, $opts, $subtest) = @_;

  if (exists $pms->{conf}->{hashbl_ignore}->{lc $value}) {
    dbg("query skipped, ignored string: $value");
    return 1;
  }

  my $hash = $self->_hash($opts, $value);
  dbg("querying $value ($hash) from $list");

  if (exists $pms->{conf}->{hashbl_ignore}->{$hash}) {
    dbg("query skipped, ignored hash: $value");
    return 1;
  }

  my $type = $list =~ s,/(A|TXT)$,,i ? uc($1) : 'A';
  my $lookup = "$hash.$list";

  my $ent = {
    rulename => $rulename,
    type => "HASHBL",
    hash => $hash,
    value => $value,
    subtest => $subtest,
  };
  $pms->{async}->bgsend_and_start_lookup($lookup, $type, undef, $ent,
    sub { my ($ent, $pkt) = @_; $self->_finish_query($pms, $ent, $pkt); },
    master_deadline => $pms->{master_deadline}
  );
}

sub _finish_query {
  my ($self, $pms, $ent, $pkt) = @_;

  my $rulename = $ent->{rulename};

  if (!$pkt) {
    # $pkt will be undef if the DNS query was aborted (e.g. timed out)
    dbg("lookup was aborted: $rulename $ent->{key}");
    return;
  }

  $pms->rule_ready($rulename); # mark rule ready for metas

  my $dnsmatch = $ent->{subtest} ? $ent->{subtest} : qr/^127\./;
  my @answer = $pkt->answer;
  foreach my $rr (@answer) {
    if ($rr->address =~ $dnsmatch) {
      dbg("$rulename: $ent->{zone} hit '$ent->{value}'");
      $ent->{value} =~ s/\@/[at]/g;
      $pms->test_log($ent->{value}, $rulename);
      $pms->got_hit($rulename, '', ruletype => 'eval');
      return;
    }
  }
}

# Version features
sub has_hashbl_bodyre { 1 }
sub has_hashbl_emails { 1 }
sub has_hashbl_uris { 1 }
sub has_hashbl_ignore { 1 }
sub has_hashbl_email_regex { 1 }
sub has_hashbl_email_welcomelist { 1 }
sub has_hashbl_email_whitelist { 1 }
sub has_hashbl_tag { 1 }

1;
