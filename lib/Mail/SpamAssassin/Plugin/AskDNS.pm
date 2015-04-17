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

=head1 USER SETTINGS

=over 4

=item rbl_timeout t [t_min] [zone]		(default: 15 3)

The rbl_timeout setting is common to all DNS querying rules (as implemented
by other plugins). It can specify a DNS query timeout globally, or individually
for each zone. When the zone parameter is specified, the settings affects DNS
queries when their query domain equals the specified zone, or is its subdomain.
See the C<Mail::SpamAssassin::Conf> POD for details on C<rbl_timeout>.

=back

=head1 RULE DEFINITIONS

=over 4

=item askdns NAME_OF_RULE query_template [rr_type [subqueryfilter]]

A query template is a string which will be expanded to produce a domain name
to be used in a DNS query. The template may include SpamAssassin tag names,
which will be replaced by their values to form a final query domain.
The final query domain must adhere to rules governing DNS domains, i.e.
must consist of fields each up to 63 characters long, delimited by dots.
There may be a trailing dot at the end, but it is redundant / carries
no semantics, because SpamAssassin uses a Net::DSN::Resolver::send method
for querying DNS, which ignores any 'search' or 'domain' DNS resolver options.
Domain names in DNS queries are case-insensitive.

A tag name is a string of capital letters, preceded and followed by an
underscore character. This syntax mirrors the add_header setting, except that
tags cannot have parameters in parenthesis when used in askdns templates.
Tag names may appear anywhere in the template - each queried DNS zone
prescribes how a query should be formed.

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
RP, HIP, IPSECKEY, KX, LOC, SRV, SSHFP, SPF.

http://www.iana.org/assignments/dns-parameters/dns-parameters.xml

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
such as RFC 5518, RFC 4408, RFC 4871, RFC 5617.  Examples of a plain text
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
address falls within the specified range: (r >= n1 && r <= n2), or
masked with a bitmask matches the specified value: (r & m) == (n & m) .

As a shorthand notation, a single quad-dotted value is equivalent to
a n-n form, i.e. it must match the returned value exactly with all its bits.

Some typical examples of a numeric filtering parameter are: 127.0.1.2,
127.0.1.20-127.0.1.39, 127.0.1.0/255.255.255.0, 0.0.0.16/0.0.0.16,
0x10/0x10, 16, 0x10 .

Lastly, the filtering parameter can be a comma-separated list of DNS status
codes (rcode), enclosed in square brackets. Rcodes can be represented either
by their numeric decimal values (0=NOERROR, 3=NXDOMAIN, ...), or their names.
See http://www.iana.org/assignments/dns-parameters for the list of names. When
testing for a rcode where rcode is nonzero, a RR type parameter is ignored
as a filter, as there is typically no answer section in a DNS reply when
rcode indicates an error.  Example: [NXDOMAIN], or [FormErr,ServFail,4,5] .

=back

=cut

package Mail::SpamAssassin::Plugin::AskDNS;

use strict;
use warnings;
use re 'taint';

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Util qw(decode_dns_question_entry);
use Mail::SpamAssassin::Logger;

use vars qw(@ISA %rcode_value $txtdata_can_provide_a_list);
@ISA = qw(Mail::SpamAssassin::Plugin);

%rcode_value = (  # http://www.iana.org/assignments/dns-parameters, RFC 6195
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

  $txtdata_can_provide_a_list = Net::DNS->VERSION >= 0.69;

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
  # modifiers /a, /d, /l, /u in suffix form were added with perl 5.13.10 (5.14)
  # currently known modifiers are [msixoadlu], but let's not be too picky here
  if (     $subtest =~ m{^       /  (.+) /  ([a-z]*) \z}xs) {
    $result = $2 ne '' ? qr{(?$2)$1} : qr{$1};
  } elsif ($subtest =~ m{^ m \s* \( (.+) \) ([a-z]*) \z}xs) {
    $result = $2 ne '' ? qr{(?$2)$1} : qr{$1};
  } elsif ($subtest =~ m{^ m \s* \[ (.+) \] ([a-z]*) \z}xs) {
    $result = $2 ne '' ? qr{(?$2)$1} : qr{$1};
  } elsif ($subtest =~ m{^ m \s* \{ (.+) \} ([a-z]*) \z}xs) {
    $result = $2 ne '' ? qr{(?$2)$1} : qr{$1};
  } elsif ($subtest =~ m{^ m \s*  < (.+)  > ([a-z]*) \z}xs) {
    $result = $2 ne '' ? qr{(?$2)$1} : qr{$1};
  } elsif ($subtest =~ m{^ m \s* (\S) (.+) \1 ([a-z]*) \z}xs) {
    $result = $2 ne '' ? qr{(?$2)$1} : qr{$1};
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
    is_admin => 1,
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
        # http://www.iana.org/assignments/dns-parameters/dns-parameters.xml
        if (grep(!/^(?:ANY|A|AAAA|MX|TXT|PTR|NAPTR|NS|SOA|CERT|CNAME|DNAME|
                       DHCID|HINFO|MINFO|RP|HIP|IPSECKEY|KX|LOC|SRV|
                       SSHFP|SPF)\z/x, @answer_types)) {
          return $Mail::SpamAssassin::Conf::INVALID_VALUE;
        }
        $query_type = 'ANY' if @answer_types > 1 || $answer_types[0] eq 'ANY';
        if (defined $subtest) {
          $subtest = parse_and_canonicalize_subtest($subtest);
          defined $subtest or return $Mail::SpamAssassin::Conf::INVALID_VALUE;
        }
        # collect tag names as used in each query template
        my @tags = $query_template =~ /_([A-Z][A-Z0-9]*)_/g;
        my %seen; @tags = grep(!$seen{$_}++, @tags);  # filter out duplicates

        # group rules by tag names used in them (to be used as a hash key)
        my $depends_on_tags = !@tags ? '' : join(',',@tags);

        # subgroup rules by a DNS RR type and a nonexpanded query template
        my $query_template_key = $query_type . ':' . $query_template;

        $self->{askdns}{$depends_on_tags}{$query_template_key} ||=
          { query => $query_template, rules => {}, q_type => $query_type,
            a_types =>  # optimization: undef means "same as q_type"
              @answer_types == 1 && $answer_types[0] eq $query_type ? undef
                                                           : \@answer_types };
        $self->{askdns}{$depends_on_tags}{$query_template_key}{rules}{$rulename}
          = $subtest;
      # dbg("askdns: rule: %s, config dep: %s, domkey: %s, subtest: %s",
      #     $rulename, $depends_on_tags, $query_template_key, $subtest);

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
sub extract_metadata {
  my($self, $opts) = @_;
  my $pms = $opts->{permsgstatus};
  my $conf = $pms->{conf};

  return if !$pms->is_dns_available;
  $pms->{askdns_map_dnskey_to_rules} = {};

  # walk through all collected askdns rules, obtain tag values whenever
  # they may become available, and launch DNS queries right after
  #
  for my $depends_on_tags (keys %{$conf->{askdns}}) {
    my @tags;
    @tags = split(/,/, $depends_on_tags)  if $depends_on_tags ne '';

    if (would_log("dbg","askdns")) {
      while ( my($query_template_key, $struct) =
                each %{$conf->{askdns}{$depends_on_tags}} ) {
        my($query_template, $query_type, $answer_types_ref, $rules) =
          @$struct{qw(query q_type a_types rules)};
        dbg("askdns: depend on tags %s, rules: %s ",
            $depends_on_tags, join(', ', keys %$rules));
      }
    }

    if (!@tags) {
      # no dependencies on tags, just call directly
      $self->launch_queries($pms,$depends_on_tags);
    } else {
      # enqueue callback for tags needed
      $pms->action_depends_on_tags(@tags == 1 ? $tags[0] : \@tags,
              sub { my($pms,@args) = @_;
                    $self->launch_queries($pms,$depends_on_tags) }
      );
    }
  }
}

# generate DNS queries - called for each set of rules
# when their tag dependencies are met
#
sub launch_queries {
  my($self, $pms, $depends_on_tags) = @_;
  my $conf = $pms->{conf};

  my %tags;
  # obtain tag/value pairs of tags we depend upon in this set of rules
  if ($depends_on_tags ne '') {
    %tags = map( ($_,$pms->get_tag($_)), split(/,/,$depends_on_tags) );
  }
  dbg("askdns: preparing queries which depend on tags: %s",
      join(', ', map($_.' => '.$tags{$_}, keys %tags)));

  # replace tag names in a query template with actual tag values
  # and launch DNS queries
  while ( my($query_template_key, $struct) =
            each %{$conf->{askdns}{$depends_on_tags}} ) {
    my($query_template, $query_type, $answer_types_ref, $rules) =
      @$struct{qw(query q_type a_types rules)};

    my @rulenames = keys %$rules;
    if (grep($conf->{scores}->{$_}, @rulenames)) {
      dbg("askdns: query template %s, type %s, rules: %s",
          $query_template,
          !$answer_types_ref ? $query_type
            : $query_type.'/'.join(',',@$answer_types_ref),
          join(', ', @rulenames));
    } else {
      dbg("askdns: query template %s, type %s, all rules disabled: %s",
          $query_template, $query_type, join(', ', @rulenames));
      next;
    }

    # collect all tag names from a template, each may occur more than once
    my @templ_tags = $query_template =~ /_([A-Z][A-Z0-9]*)_/gs;

    # filter out duplicate tag names, and tags with undefined or empty value
    my %seen;
    @templ_tags = grep(!$seen{$_}++ && defined $tags{$_} && $tags{$_} ne '',
                       @templ_tags);

    my %templ_vals;  # values that each tag takes
    for my $t (@templ_tags) {
      my %seen;
      # a tag value may be a space-separated list,
      # store it as an arrayref, removing duplicate values
      $templ_vals{$t} = [ grep(!$seen{$_}++, split(' ',$tags{$t})) ];
    }

    # count through all tag value tuples
    my @digit = (0) x @templ_tags;  # counting accumulator
OUTER:
    for (;;) {
      my %current_tag_val;  # maps a tag name to its current iteration value
      for my $j (0 .. $#templ_tags) {
        my $t = $templ_tags[$j];
        $current_tag_val{$t} = $templ_vals{$t}[$digit[$j]];
      }
      local $1;
      my $query_domain = $query_template;
      $query_domain =~ s{_([A-Z][A-Z0-9]*)_}
                        { defined $current_tag_val{$1} ? $current_tag_val{$1}
                                                       : '' }ge;

      # the $dnskey identifies this query in AsyncLoop's pending_lookups
      my $dnskey = join(':', 'askdns', $query_type, $query_domain);
      dbg("askdns: expanded query %s, dns key %s", $query_domain, $dnskey);

      if ($query_domain eq '') {
        # ignore, just in case
      } else {
        if (!exists $pms->{askdns_map_dnskey_to_rules}{$dnskey}) {
          $pms->{askdns_map_dnskey_to_rules}{$dnskey} =
             [ [$query_type, $answer_types_ref, $rules] ];
        } else {
          push(@{$pms->{askdns_map_dnskey_to_rules}{$dnskey}},
               [$query_type, $answer_types_ref, $rules] );
        }
        # lauch a new DNS query for $query_type and $query_domain
        my $ent = $pms->{async}->bgsend_and_start_lookup(
          $query_domain, $query_type, undef,
          { key => $dnskey, zone => $query_domain },
          sub { my ($ent2,$pkt) = @_;
                $self->process_response_packet($pms, $ent2, $pkt, $dnskey) },
          master_deadline => $pms->{master_deadline} );
        # these rules are now underway;  unless the rule hits, these will
        # not be considered "finished" until harvest_dnsbl_queries() completes
        $pms->register_async_rule_start($dnskey) if $ent;
      }

      last  if !@templ_tags;
      # increment accumulator, little-endian
      for (my $j = 0;  ; $j++) {
        last  if ++$digit[$j] <= $#{$templ_vals{$templ_tags[$j]}};
        $digit[$j] = 0;  # and carry
        last OUTER  if $j >= $#templ_tags;
      }
    }
  }
}

sub process_response_packet {
  my($self, $pms, $ent, $pkt, $dnskey) = @_;

  my $conf = $pms->{conf};
  my %rulenames_hit;

  # map a dnskey back to info on queries which caused this DNS lookup
  my $queries_ref = $pms->{askdns_map_dnskey_to_rules}{$dnskey};

  my($header, @question, @answer, $qtype, $rcode);
  # NOTE: $pkt will be undef if the DNS query was aborted (e.g. timed out)
  if ($pkt) {
    @answer = $pkt->answer;
    $header = $pkt->header;
    @question = $pkt->question;
    $qtype = uc $question[0]->qtype  if @question;
    $rcode = uc $header->rcode  if $header;  # 'NOERROR', 'NXDOMAIN', ...

    # NOTE: qname is encoded in RFC 1035 zone format, decode it
    dbg("askdns: answer received, rcode %s, query %s, answer has %d records",
        $rcode,
        join(', ', map(join('/', decode_dns_question_entry($_)), @question)),
        scalar @answer);

    if (defined $rcode && exists $rcode_value{$rcode}) {
      # Net::DNS return a rcode name for codes it knows about,
      # and returns a number for the rest; we deal with numbers from here on
      $rcode = $rcode_value{$rcode}  if exists $rcode_value{$rcode};
    }
  }
  if (!@answer) {
    # a trick to make the following loop run at least once, so that we can
    # evaluate also rules which only care for rcode status
    @answer = ( undef );
  }

  # NOTE:  $rr->rdatastr returns the result encoded in a DNS zone file
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
  # The same goes for RFC 4408 (SPF), RFC 4871 (DKIM), RFC 5617 (ADSP),
  # draft-kucherawy-dmarc-base (DMARC), ...

  for my $rr (@answer) {
    my($rr_rdatastr, $rdatanum, $rr_type);
    if (!$rr) {
      # special case, no answer records, only rcode can be tested
    } else {
      $rr_type = uc $rr->type;
      if ($rr->UNIVERSAL::can('txtdata')) {  # TXT, SPF
        # join with no intervening spaces, as per RFC 5518
        if ($txtdata_can_provide_a_list || $rr_type ne 'TXT') {
          $rr_rdatastr = join('', $rr->txtdata);  # txtdata() in list context!
        } else {  # char_str_list() is only available for TXT records
          $rr_rdatastr = join('', $rr->char_str_list);  # historical
        }
      } else {
        $rr_rdatastr = $rr->rdatastr;
        if ($rr_type eq 'A' &&
            $rr_rdatastr =~ m/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\z/) {
          $rdatanum = Mail::SpamAssassin::Util::my_inet_aton($rr_rdatastr);
        }
      }
    # dbg("askdns: received rr type %s, data: %s", $rr_type, $rr_rdatastr);
    }

    my $j = 0;
    for my $q_tuple (!ref $queries_ref ? () : @$queries_ref) {
      next  if !$q_tuple;
      my($query_type, $answer_types_ref, $rules) = @$q_tuple;

      next  if !defined $qtype || $query_type ne $qtype;
      $answer_types_ref = [$query_type]  if !defined $answer_types_ref;

      # mark rule as done
      $pms->{askdns_map_dnskey_to_rules}{$dnskey}[$j++] = undef;

      while (my($rulename,$subtest) = each %$rules) {
        my $match;
        local($1,$2,$3);
        if (ref $subtest eq 'HASH') {  # a list of DNS rcodes (as hash keys)
          $match = 1  if $subtest->{$rcode};
        } elsif ($rcode != 0) {
          # skip remaining tests on DNS error
        } elsif (!defined($rr_type) ||
                 !grep($_ eq 'ANY' || $_ eq $rr_type, @$answer_types_ref) ) {
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
            !defined $n2  ? ($rdatanum & $n1) &&                  # mask only
                              (($rdatanum & 0xff000000) == 0x7f000000)  # 127/8
          : $delim eq '-' ? $rdatanum >= $n1 && $rdatanum <= $n2  # range
          : $delim eq '/' ? ($rdatanum & $n2) == ($n1 & $n2)      # value/mask
          : 0;  
        }
        if ($match) {
          $self->askdns_hit($pms, $ent->{query_domain}, $qtype,
                            $rr_rdatastr, $rulename);
          $rulenames_hit{$rulename} = 1;
        }
      }
    }
  }
  # these rules have completed (since they got at least 1 hit)
  $pms->register_async_rule_finish($_)  for keys %rulenames_hit;
}

sub askdns_hit {
  my($self, $pms, $query_domain, $qtype, $rr_rdatastr, $rulename) = @_;

  $rr_rdatastr = '' if !defined $rr_rdatastr;  # e.g. with rules testing rcode
  dbg('askdns: domain "%s" listed (%s): %s',
      $query_domain, $rulename, $rr_rdatastr);

  # only the first hit will show in the test log report, even if
  # an answer section matches more than once - got_hit() handles this
  $pms->clear_test_state;
  $pms->test_log(sprintf("%s %s:%s", $query_domain,$qtype,$rr_rdatastr));
  $pms->got_hit($rulename, 'ASKDNS: ', ruletype => 'askdns');  # score=>$score
}

1;
