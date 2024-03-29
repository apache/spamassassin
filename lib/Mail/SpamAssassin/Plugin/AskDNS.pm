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

AskDNS - form a DNS query using tag values, and look up the DNSxL lists

=head1 SYNOPSIS

  loadplugin  Mail::SpamAssassin::Plugin::AskDNS
  askdns D_IN_DWL _DKIMDOMAIN_._vouch.dwl.spamhaus.org TXT /\b(transaction|list|all)\b/

=head1 DESCRIPTION

Using a DNS query template as specified in a parameter of a askdns rule,
the plugin replaces tag names as found in the template with their values
and launches DNS queries as soon as tag values become available. When DNS
responses trickle in, filters them according to the requested DNS resource
record type and optional subrule filtering expression, yielding a rule hit
if a response meets filtering conditions.

=head1 RULE DEFINITIONS AND PRIVILEGED SETTINGS

=over 4

=item askdns NAME_OF_RULE query_template [rr_type [subqueryfilter]]

A query template is a string which will be expanded to produce a domain name
to be used in a DNS query. The template may include SpamAssassin tag names,
which will be replaced by their values to form a final query domain.

The final query domain must adhere to rules governing DNS domains, i.e.
must consist of fields each up to 63 characters long, delimited by dots,
not exceeding 255 characters. International domain names (in UTF-8) are
allowed and will be encoded to ASCII-compatible encoding (ACE) according
to IDN rules. Syntactically invalid resulting queries will be discarded
by the DNS resolver code (with some info warnings).

There may be a trailing dot at the end, but it is redundant / carries no
semantics, because SpamAssassin uses a Net::DSN::Resolver::send method for
querying DNS, which ignores any 'search' or 'domain' DNS resolver options.
Domain names in DNS queries are case-insensitive.

A tag name is a string of capital letters, preceded and followed by an
underscore character.  This syntax mirrors the add_header setting, except
that tags cannot have parameters in parenthesis when used in askdns
templates (exceptions found below).  Tag names may appear anywhere in the
template - each queried DNS zone prescribes how a query should be formed.

Special supported tag HEADER() can be used to query any header content,
using same header names/modifiers that as header rules support.  For example
_HEADER(Reply-To:addr:domain)_ can be used to query the trimmed domain part
of Reply-To address.  See Mail::SpamAssassin::Conf documentation about
header rules.

A query template may contain any number of tag names including none,
although in the most common anticipated scenario exactly one tag name would
appear in each askdns rule. Specified tag names are considered dependencies.
Askdns rules with dependencies on the same set of tags are grouped, and all
queries in a group are launched as soon as all their dependencies are met,
i.e. when the last of the awaited tag values becomes available by a call
to set_tag() from some other plugin or elsewhere in the SpamAssassin code.

Launched queries from all askdns rules are grouped too according to a pair
of: query type and an expanded query domain name. Even if there are multiple
rules producing the same type/domain pair, only one DNS query is launched,
and a reply to such query contributes to all the constituent rules.

A tag may produce none, one or multiple values. Askdns rules awaiting for
a tag which never receives its value never result in a DNS query. Tags which
produce multiple values will result in multiple queries launched, each with
an expanded template using one of the tag values. An example is a DKIMDOMAIN
tag which yields a list of signing domains, one for each valid signature in
a signed message.

When more than one distinct tag name appears in a template, each potentially
resulting in multiple values, a Cartesian product is formed, and each tuple
results in a launch of one DNS query (duplicates excluded). For example,
a query template _A_._B_.example._A_.com where tag A is a list (11,22)
and B is (xx,yy,zz), will result in queries: 11.xx.example.11.com,
22.xx.example.22.com, 11.yy.example.11.com, 22.yy.example.22.com,
11.zz.example.11.com, 22.zz.example.22.com .

A parameter rr_type following the query template is a comma-separated list
of expected DNS resource record (RR) types. Missing rr_type parameter implies
an 'A'. A DNS result may bring resource records of multiple types, but only
resource records of a type found in the rr_type parameter list are considered,
other resource records found in the answer section of a DNS reply are ignored
for this rule. A value ANY in the rr_type parameter list matches any resource
record type. An empty DNS answer section does not match ANY.

The rr_type parameter not only provides a filter for RR types found in
the DNS answer, but also determines the DNS query type. If only a single
RR type is specified in the parameter (e.g. TXT), than this is also the RR
type of a query. When more than one RR type is specified (e.g. A, AAAA, TXT)
or if ANY is specified, then the DNS query type will be ANY and the rr_type
parameter will only act as a filter on a result.

Currently recognized RR types in the rr_type parameter are: ANY, A, AAAA,
MX, TXT, PTR, NAPTR, NS, SOA, CERT, CNAME, DNAME, DHCID, HINFO, MINFO,
RP, HIP, IPSECKEY, KX, LOC, GPOS, SRV, OPENPGPKEY, SSHFP, SPF, TLSA, URI,
CAA, CSYNC.

https://www.iana.org/assignments/dns-parameters/dns-parameters.xml

The last optional parameter of a rule is a filtering expression, a.k.a. a
subrule. Its function is much like the subrule in URIDNSBL plugin rules,
or in the check_rbl eval rules. The main difference is that with askdns
rules there is no need to manually group rules according to their queried
zone, as the grouping is automatic and duplicate queries are implicitly
eliminated.

The subrule filtering parameter can be: a plain string, a regular expression,
a single numerical value or a pair of numerical values, or a list of rcodes
(DNS status codes of a response). Absence of the filtering parameter implies
no filtering, i.e. any positive DNS response (rcode=NOERROR) of the requested
RR type will result in a rule hit, regardless of the RR value returned with
the response.

When a plain string is used as a filter, it must be enclosed in single or
double quotes. For the rule to hit, the response must match the filtering
string exactly, and a RR type of a response must match the query type.
Typical use is an exact text string for TXT queries, or an exact quad-dotted
IPv4 address. In case of a TXT or SPF resource record which can return
multiple character-strings (as defined in Section 3.3 of [RFC1035]), these
strings are concatenated with no delimiters before comparing the result
to the filtering string. This follows requirements of several documents,
such as RFC 5518, RFC 7208, RFC 4871, RFC 5617.  Examples of a plain text
filtering parameter: "127.0.0.1", "transaction", 'list' .

A regular expression follows a familiar perl syntax like /.../ or m{...}
optionally followed by regexp flags (such as 'i' for case-insensitivity).
If a DNS response matches the requested RR type and the regular expression,
the rule hits.  Examples: /^127\.0\.0\.\d+$/, m{\bdial up\b}i .

A single numerical value can be a decimal number, or a hexadecimal number
prefixed by 0x. Such numeric filtering expression is typically used with
RR type-A DNS queries. The returned value (an IPv4 address) is masked
with a specified filtering value and tested to fall within a 127.0.0.0/8
network range - the rule hits if the result is nonzero:
((r & n) != 0) && ((r & 0xff000000) == 0x7f000000).  An example: 0x10 .

A pair of numerical values (each a decimal, hexadecimal or quad-dotted)
delimited by a '-' specifies an IPv4 address range, and a pair of values
delimited by a '/' specifies an IPv4 address followed by a bitmask. Again,
this type of filtering expression is primarily intended with RR type-A
DNS queries. The rule hits if the RR type matches, and the returned IP
address falls within the specified range: (r E<gt>= n1 && r E<lt>= n2), or
masked with a bitmask matches the specified value: (r & m) == (n & m) .

As a shorthand notation, a single quad-dotted value is equivalent to
a n-n form, i.e. it must match the returned value exactly with all its bits.

Some typical examples of a numeric filtering parameter are: 127.0.1.2,
127.0.1.20-127.0.1.39, 127.0.1.0/255.255.255.0, 0.0.0.16/0.0.0.16,
0x10/0x10, 16, 0x10 .

Lastly, the filtering parameter can be a comma-separated list of DNS status
codes (rcode), enclosed in square brackets. Rcodes can be represented either
by their numeric decimal values (0=NOERROR, 3=NXDOMAIN, ...), or their names.
See https://www.iana.org/assignments/dns-parameters for the list of names. When
testing for a rcode where rcode is nonzero, a RR type parameter is ignored
as a filter, as there is typically no answer section in a DNS reply when
rcode indicates an error.  Example: [NXDOMAIN], or [FormErr,ServFail,4,5] .

=back

=head1 NOTES

DNS timeout can be set with C<rbl_timeout> option.  See the
C<Mail::SpamAssassin::Conf> POD for details on C<rbl_timeout>.

=cut

package Mail::SpamAssassin::Plugin::AskDNS;

use strict;
use warnings;
use re 'taint';

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Util qw(decode_dns_question_entry idn_to_ascii
                                compile_regexp is_fqdn_valid);
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Constants qw(:ip);
use version 0.77;

our @ISA = qw(Mail::SpamAssassin::Plugin);

our %rcode_value = (  # https://www.iana.org/assignments/dns-parameters, RFC 6195
  NOERROR => 0,  FORMERR => 1, SERVFAIL => 2, NXDOMAIN => 3, NOTIMP => 4,
  REFUSED => 5,  YXDOMAIN => 6, YXRRSET => 7, NXRRSET => 8, NOTAUTH => 9,
  NOTZONE => 10, BADVERS => 16, BADSIG => 16, BADKEY => 17, BADTIME => 18,
  BADMODE => 19, BADNAME => 20, BADALG => 21, BADTRUNC => 22,
);

sub new {
  my($class,$sa_main) = @_;

  $class = ref($class) || $class;
  my $self = $class->SUPER::new($sa_main);
  bless($self, $class);

  $self->set_config($sa_main->{conf});

  return $self;
}

# ---------------------------------------------------------------------------

# Accepts argument as a string in single or double quotes, or as a regular
# expression in // or m{} notation, or as a numerical value or a pair of
# numerical values, or as a bracketed and comma-separated list of DNS rcode
# names or their numerical codes. Recognized numerical forms are: m, n1-n2,
# or n/m, where n,n1,n2,m can be any of: decimal digits, 0x followed by
# up to 8 hexadecimal digits, or an IPv4 address in quad-dotted notation.
# The argument is checked for syntax, undef is returned on syntax errors.
# A string that looks like a regular expression is converted to a compiled
# Regexp object and returned as a result. Otherwise, numeric components of
# the remaining three forms are converted as follows: hex or decimal numeric
# strings are converted to a number and a quad-dot is converted to a number,
# then components are reassembled into a string delimited by '-' or '/'.
# As a special backward compatibility measure, a single quad-dot (with no
# second number) is converted into n-n, to distinguish it from a traditional
# mask-only form. A list or rcodes is returned as a hashref, where keys
# represent specified numerical rcodes.
#
# Arguments like the following are anticipated:
#   "127.0.0.1", "some text", 'some "more" text',
#   /regexp/flags, m{regexp}flags,
#   127.0.1.2  (same as 127.0.1.2-127.0.1.2 or 127.0.1.2/255.255.255.255)
#   127.0.1.20-127.0.1.39  (= 0x7f000114-0x7f000127 or 2130706708-2130706727)
#   0.0.0.16/0.0.0.16  (same as 0x10/0x10 or 16/0x10 or 16/16)
#   16  (traditional style mask-only, same as 0x10)
#   [NXDOMAIN], [FormErr,ServFail,4,5]
#
sub parse_and_canonicalize_subtest {
  my($subtest) = @_;
  my $result;

  local($1,$2,$3);
  if ($subtest =~ m{^/ .+ / [a-z]* \z}xs ||
      $subtest =~ m{^m (\W) .+ (\W) [a-z]* \z}xs) {
    my ($rec, $err) = compile_regexp($subtest, 1);
    if (!$rec) {
      warn "askdns: subtest compile failed: '$subtest': $err\n";
    } else {
      $result = $rec;
    }
  } elsif ($subtest =~ m{^ (["']) (.*) \1 \z}xs) {  # quoted string
    $result = $2;
  } elsif ($subtest =~ m{^ \[ ( (?:[A-Z]+|\d+)
                                (?: \s* , \s* (?:[A-Z]+|\d+) )* ) \] \z}xis) {
    # a comma-separated list of rcode names or their decimal values
    my @rcodes = split(/\s*,\s*/, uc $1);
    for (@rcodes) { $_ = $rcode_value{$_}  if exists $rcode_value{$_} }
    return  if grep(!/^\d+\z/, @rcodes);
    # a hashref indicates a list of DNS rcodes (stored as hash keys)
    $result = { map( ($_,1), @rcodes) };
  } elsif ($subtest =~ m{^ ([^/-]+) (?: ([/-]) (.+) )? \z}xs) {
    my($n1,$delim,$n2) = ($1,$2,$3);
    my $any_quad_dot;
    for ($n1,$n2) {
      if (!defined $_) {
        # ok, $n2 may not exist
      } elsif (/^\d{1,10}\z/) {
        $_ = 0 + $_;   # decimal string -> number
      } elsif (/^0x[0-9a-zA-Z]{1,8}\z/) {
        $_ = hex($_);  # hex string -> number
      } elsif (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\z/) {
        $_ = Mail::SpamAssassin::Util::my_inet_aton($_);  # quad-dot -> number
        $any_quad_dot = 1;
      } else {
        return;
      }
    }
    $result = defined $n2 ? $n1.$delim.$n2
            : $any_quad_dot ? $n1.'-'.$n1 : "$n1";
  }
  return $result;
}

sub set_config {
  my($self, $conf) = @_;
  my @cmds;

  push(@cmds, {
    setting => 'askdns',
    is_priv => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
    code => sub {
      my($self, $key, $value, $line) = @_;
      local($1,$2,$3,$4);
      if (!defined $value || $value =~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      } elsif ($value !~ /^ (\S+) \s+ (\S+)
                            (?: \s+ ([A-Za-z0-9,]+)
                                (?: \s+ (.*?) )?  )? \s* $/xs) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      } else {
        my($rulename,$query_template,$query_type,$subtest) = ($1,$2,$3,$4);
        $query_type = 'A' if !defined $query_type;
        $query_type = uc $query_type;
        my @answer_types = split(/,/, $query_type);
        # https://www.iana.org/assignments/dns-parameters/dns-parameters.xml
        if (grep(!/^(?:ANY|A|AAAA|MX|TXT|PTR|NAPTR|NS|SOA|CERT|CNAME|DNAME|
                       DHCID|HINFO|MINFO|RP|HIP|IPSECKEY|KX|LOC|GPOS|SRV|
                       OPENPGPKEY|SSHFP|SPF|TLSA|URI|CAA|CSYNC)\z/x,
                 @answer_types)) {
          return $Mail::SpamAssassin::Conf::INVALID_VALUE;
        }
        $query_type = 'ANY' if @answer_types > 1 || $answer_types[0] eq 'ANY';
        if (defined $subtest) {
          $subtest = parse_and_canonicalize_subtest($subtest);
          defined $subtest or return $Mail::SpamAssassin::Conf::INVALID_VALUE;
        }

        # initialize rule structure
        $self->{askdns}{$rulename}{query} = $query_template;
        $self->{askdns}{$rulename}{q_type} = $query_type;
        $self->{askdns}{$rulename}{a_types} = \@answer_types;
        $self->{askdns}{$rulename}{subtest} = $subtest;
        $self->{askdns}{$rulename}{tags} = ();

        # collect tag names as used in each query template
        # also support common HEADER(arg) tag which does $pms->get(arg)
        my @tags = $query_template =~ /_([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*(?:\(.*?\))?)_/g;
        # save rule to tag dependencies
        $self->{askdns}{$rulename}{tags}{$_} = 1 foreach (@tags);

        # just define the test so that scores and lint works
        $self->{parser}->add_test($rulename, undef,
                                  $Mail::SpamAssassin::Conf::TYPE_EMPTY_TESTS);
      }
    }
  });

  $conf->{parser}->register_commands(\@cmds);
}

# run as early as possible, launching DNS queries as soon as their
# dependencies are fulfilled
#
sub check_dnsbl {
  my($self, $opts) = @_;

  my $pms = $opts->{permsgstatus};
  my $conf = $pms->{conf};

  return if !$pms->is_dns_available();

  # walk through all collected askdns rules, obtain tag values whenever
  # they may become available, and launch DNS queries right after
  foreach my $rulename (keys %{$conf->{askdns}}) {
    if (!$conf->{scores}->{$rulename}) {
      dbg("askdns: skipping disabled rule $rulename");
      next;
    }
    my @tags = sort keys %{$conf->{askdns}{$rulename}{tags}};
    if (@tags) {
      dbg("askdns: rule %s depends on tags: %s", $rulename,
          join(', ', @tags));
      $pms->action_depends_on_tags(@tags == 1 ? $tags[0] : \@tags,
            sub { my($pms,@args) = @_;
                  $self->launch_queries($pms,$rulename,\@tags) }
      );
    } else {
      # no dependencies on tags, just call directly
      $self->launch_queries($pms,$rulename,[]);
    }
  }
}

# generate DNS queries - called for each rule when its tag dependencies
# are met
#
sub launch_queries {
  my($self, $pms, $rulename, $tags) = @_;

  my $arule = $pms->{conf}->{askdns}{$rulename};
  my $query_tmpl = $arule->{query};
  my $queries;
  if (@$tags) {
    if (!exists $pms->{askdns_qtmpl_cache}{$query_tmpl}) {
      # replace tags in query template
      # iterate through each tag, replacing list of strings as we go
      my %q_iter = ( "$query_tmpl" => 1 );
      foreach my $tag (@$tags) {
        # cache tag values locally
        if (!exists $pms->{askdns_tag_cache}{$tag}) {
          my $valref = $pms->get_tag_raw($tag);
          my @vals = grep { defined $_ && $_ ne '' } (ref $valref ? @$valref : $valref);
          # Paranoid check for undefined tag
          if (!@vals) {
            dbg("askdns: skipping rule $rulename, no value found for tag: $tag");
            return;
          }
          $pms->{askdns_tag_cache}{$tag} = \@vals;
        }
        my %q_iter_new;
        foreach my $q (keys %q_iter) {
          # handle space separated multi-valued tags
          foreach my $val (@{$pms->{askdns_tag_cache}{$tag}}) {
            my $qtmp = $q;
            $qtmp =~ s/\Q_${tag}_\E/${val}/g;
            $q_iter_new{$qtmp} = 1;
          }
        }
        %q_iter = %q_iter_new;
      }
      # cache idn'd queries
      my @q_arr;
      push @q_arr, idn_to_ascii($_) foreach (keys %q_iter);
      $pms->{askdns_qtmpl_cache}{$query_tmpl} = \@q_arr;
    }
    $queries = $pms->{askdns_qtmpl_cache}{$query_tmpl};
  } else {
    push @$queries, idn_to_ascii($query_tmpl);
  }

  foreach my $query (@$queries) {
    if (!is_fqdn_valid($query, 1)) {
      dbg("askdns: skipping invalid query ($rulename): $query");
      next;
    }
    dbg("askdns: launching query ($rulename): $query");
    my $ret = $pms->{async}->bgsend_and_start_lookup(
      $query, $arule->{q_type}, undef,
        { rulename => $rulename, type => 'AskDNS' },
        sub { my ($ent,$pkt) = @_;
              $self->process_response_packet($pms, $ent, $pkt, $rulename) },
        master_deadline => $pms->{master_deadline}
    );
    $pms->rule_ready($rulename) if !$ret; # mark ready if nothing launched
  }
}

sub process_response_packet {
  my($self, $pms, $ent, $pkt, $rulename) = @_;

  # NOTE: $pkt will be undef if the DNS query was aborted (e.g. timed out)
  return if !$pkt;

  my @question = $pkt->question;
  return if !@question;

  $pms->rule_ready($rulename); # mark rule ready for metas

  my @answer = $pkt->answer;
  my $rcode = uc $pkt->header->rcode;  # 'NOERROR', 'NXDOMAIN', ...

  # NOTE: qname is encoded in RFC 1035 zone format, decode it
  dbg("askdns: answer received (%s), rcode %s, query %s, answer has %d records",
      $rulename, $rcode,
      join(', ', map(join('/', decode_dns_question_entry($_)), @question)),
      scalar @answer);

  # Net::DNS return a rcode name for codes it knows about,
  # and returns a number for the rest; we deal with numbers from here on
  $rcode = $rcode_value{$rcode}  if exists $rcode_value{$rcode};

  # a trick to make the following loop run at least once, so that we can
  # evaluate also rules which only care for rcode status
  @answer = (undef)  if !@answer;

  # NOTE:  $rr->rdstring returns the result encoded in a DNS zone file
  # format, i.e. enclosed in double quotes if a result contains whitespace
  # (or other funny characters), and may use \DDD encoding or \X quoting as
  # per RFC 1035.  Using $rr->txtdata instead avoids this unnecessary encoding
  # step and a need for decoding by a caller, returning an unmodified string.
  # Caveat: in case of multiple RDATA <character-string> fields contained
  # in a resource record (TXT, SPF, HINFO), starting with Net::DNS 0.69
  # the $rr->txtdata in a list context returns these strings as a list.
  # The $rr->txtdata in a scalar context always returns a single string
  # with <character-string> fields joined by a single space character as
  # a separator.  The $rr->txtdata in Net::DNS 0.68 and older returned
  # such joined space-separated string even in a list context.

  # RFC 5518: If the RDATA in a TXT record contains multiple
  # character-strings (as defined in Section 3.3 of [RFC1035]),
  # the code handling such reply from DNS MUST assemble all of these
  # marshaled text blocks into a single one before any syntactical
  # verification takes place.
  # The same goes for RFC 7208 (SPF), RFC 4871 (DKIM), RFC 5617 (ADSP),
  # draft-kucherawy-dmarc-base (DMARC), ...

  my $arule = $pms->{conf}->{askdns}{$rulename};
  my $subtest = $arule->{subtest};

  for my $rr (@answer) {
    my($rr_rdatastr, $rdatanum, $rr_type);
    if (!$rr) {
      # special case, no answer records, only rcode can be tested
    } else {
      $rr_type = uc $rr->type;
      if ($rr_type eq 'A') {
        $rr_rdatastr = $rr->address;
        if ($rr_rdatastr =~ m/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\z/) {
          $rdatanum = Mail::SpamAssassin::Util::my_inet_aton($rr_rdatastr);
        }

      } elsif ($rr->UNIVERSAL::can('txtdata')) {
        # TXT, SPF: join with no intervening spaces, as per RFC 5518
        $rr_rdatastr = join('', $rr->txtdata);  # txtdata() in list context!
        # Net::DNS attempts to decode text strings in a TXT record as UTF-8,
        # which is undesired: octets failing the UTF-8 decoding are converted
        # to a Unicode "replacement character" U+FFFD (encoded as octets
        # \x{EF}\x{BF}\x{BD} in UTF-8), and ASCII text is unnecessarily
        # flagged as perl native characters (utf8 flag on), which can be
        # disruptive on later processing, e.g. implicitly upgrading strings
        # on concatenation. Unfortunately there is no way of legally bypassing
        # the UTF-8 decoding by Net::DNS::RR::TXT in Net::DNS::RR::Text.
        # Try to minimize damage by encoding back to UTF-8 octets:
        utf8::encode($rr_rdatastr)  if utf8::is_utf8($rr_rdatastr);

      } else {
        $rr_rdatastr = $rr->rdstring;
        utf8::encode($rr_rdatastr)  if utf8::is_utf8($rr_rdatastr);
      }
      # dbg("askdns: received rr type %s, data: %s", $rr_type, $rr_rdatastr);
    }

    my $match;
    local($1,$2,$3);
    if (ref $subtest eq 'HASH') {  # a list of DNS rcodes (as hash keys)
      $match = 1  if $subtest->{$rcode};
    } elsif ($rcode != 0) {
      # skip remaining tests on DNS error
    } elsif (!defined($rr_type) ||
             !grep($_ eq 'ANY' || $_ eq $rr_type, @{$arule->{a_types}}) ) {
      # skip remaining tests on wrong RR type
    } elsif (!defined $subtest) {
      $match = 1;  # any valid response of the requested RR type matches
    } elsif (ref $subtest eq 'Regexp') {  # a regular expression
      $match = 1  if $rr_rdatastr =~ $subtest;
    } elsif ($rr_rdatastr eq $subtest) {  # exact equality
      $match = 1;
    } elsif (defined $rdatanum &&
             $subtest =~ m{^ (\d+) (?: ([/-]) (\d+) )? \z}x) {
      my($n1,$delim,$n2) = ($1,$2,$3);
      $match =
        !defined $n2 ? ($rdatanum & $n1) &&                     # mask only
                       (($rdatanum & 0xff000000) == 0x7f000000) # 127/8
        : $delim eq '-' ? $rdatanum >= $n1 && $rdatanum <= $n2  # range
        : $delim eq '/' ? ($rdatanum & $n2) == (int($n1) & $n2) # value/mask
        : 0; # notice int($n1) to fix perl ~5.14 taint bug (Bug 7725)
    }
    if ($match) {
      $self->askdns_hit($pms, $ent->{query_domain}, $question[0]->qtype,
                        $rr_rdatastr, $rulename);
    }
  }
}

sub askdns_hit {
  my($self, $pms, $query_domain, $qtype, $rr_rdatastr, $rulename) = @_;

  $rr_rdatastr = '' if !defined $rr_rdatastr;  # e.g. with rules testing rcode
  dbg('askdns: domain "%s" listed (%s): %s',
      $query_domain, $rulename, $rr_rdatastr);

  # only the first hit will show in the test log report, even if
  # an answer section matches more than once - got_hit() handles this
  $pms->test_log(sprintf("%s %s:%s", $query_domain,$qtype,$rr_rdatastr), $rulename);
  $pms->got_hit($rulename, 'ASKDNS: ', ruletype => 'askdns');  # score=>$score
}

# Version features
sub has_tag_header { 1 } # HEADER() was implemented together with Conf::feature_get_host # Bug 7734

1;
