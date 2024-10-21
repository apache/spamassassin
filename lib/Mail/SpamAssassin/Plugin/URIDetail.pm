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
# TODO: where are the tests?

=head1 NAME

URIDetail - test URIs using detailed URI information

=head1 SYNOPSIS

This plugin creates a new rule test type, known as "uri_detail".  These
rules apply to all URIs found in the message.

  loadplugin    Mail::SpamAssassin::Plugin::URIDetail

=head1 RULE DEFINITIONS AND PRIVILEGED SETTINGS

The format for defining a rule is as follows:

  uri_detail SYMBOLIC_TEST_NAME key1 =~ /value1/i  key2 !~ /value2/ ...

Supported keys are:

C<raw> is the raw URI prior to any cleaning
(e.g. "http://spamassassin.apache%2Eorg/").

C<type> is the tag(s) which referenced the raw_uri.  I<parsed> is a
faked type which specifies that the raw_uri was parsed from the
rendered text.

C<cleaned> is a list including the raw URI and various cleaned
versions of the raw URI (http://spamassassin.apache%2Eorg/,
https://spamassassin.apache.org/).

C<text> is the anchor text(s) (text between E<lt>aE<gt> and E<lt>/aE<gt>) that
linked to the raw URI.

C<domain> is the domain(s) found in the cleaned URIs, as trimmed to
registrar boundary by Mail::SpamAssassin::Util::RegistrarBoundaries(3).

C<host> is the full host(s) in the cleaned URIs. (Supported since SA 3.4.5)

Example rule for matching a URI where the raw URI matches "%2Ebar",
the domain "bar.com" is found, and the type is "a" (an anchor tag).

  uri_detail TEST1 raw =~ /%2Ebar/  domain =~ /^bar\.com$/  type =~ /^a$/

Example rule to look for suspicious "https" links:

  uri_detail FAKE_HTTPS text =~ /\bhttps:/  cleaned !~ /\bhttps:/

Regular expressions should be delimited by slashes.

Negating matches is supported in SpamAssassin 4.0.2 or higher by prefixing the key with an exclamation mark.

Example rule to look for links where the text contains "id.me" but the host is not "id.me":

  uri_detail FAKE_ID_ME   text =~ /\bid\.me\b/  !host =~ /^id\.me$/

The difference between '!key =~ ...' and 'key !~ ...' is due to the fact that keys can contain multiple values.
'!key =~ ...' will be true if none of the values match the regex, while 'key !~ ...' will be true if any of the values
do not match the regex.

For example, consider the following data structure:

  {
    host => {
      'id.me' => 1,
      'example.com' => 1,
    },
    text => [
      'Login to ID.me'
    ]
  }

The rule 'host !~ /^id\.me$/' would be true, because 'example.com' does not match the regex.
The rule '!host =~ /^id\.me$/' would be false, because it is the logical negation of 'host =~ /^id\.me$/'
which is true because 'id.me' matches the regex.

There must not be any whitespace between the key and the negation operator.

=cut

package Mail::SpamAssassin::Plugin::URIDetail;
use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Util qw(untaint_var compile_regexp);

use strict;
use warnings;
# use bytes;
use re 'taint';

our @ISA = qw(Mail::SpamAssassin::Plugin);

# constructor
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->register_eval_rule("check_uri_detail");

  $self->set_config($mailsaobject->{conf});

  return $self;
}

sub set_config {
  my ($self, $conf) = @_;
  my @cmds;

  my $pluginobj = $self;        # allow use inside the closure below

  push (@cmds, {
    setting => 'uri_detail',
    is_priv => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;

      if ($value !~ /^(\S+)\s+(.+)$/) {
	return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      my $name = $1;
      my $def = $2;
      my $added_criteria = 0;

      # if this matches a regex, it strips slashes  
      while ($def =~ m{\s*([!\w]+)\b\s*([\=\!]\~)\s*((?:/.*?/|m(\W).*?\4)[imsx]*)(?=\s|$)}g) {
	my $target = $1;
	my $op = $2;
	my $pattern = $3;
        my $neg = 0;

	if ($target !~ /^!?(?:raw|type|cleaned|text|domain|host)$/) {
	    return $Mail::SpamAssassin::Conf::INVALID_VALUE;
	}

	my ($rec, $err) = compile_regexp($pattern, 1);
	if (!$rec) {
	  dbg("config: uri_detail invalid regexp '$pattern': $err");
	  return $Mail::SpamAssassin::Conf::INVALID_VALUE;
	}

	dbg("config: uri_detail adding ($target $op /$rec/) to $name");
        if ($target =~ /^!(.*)/) {
          $target = $1;
          $neg = 1;
        }
        $conf->{parser}->{conf}->{uri_detail}->{$name}->{$target} =
          [$op, $rec, $neg];
	$added_criteria = 1;
      }

      if ($added_criteria) {
	dbg("config: uri_detail added $name\n");
	$conf->{parser}->add_test($name, 'check_uri_detail()',
	  $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
      } 
      else {
	warn "config: failed to add invalid rule $name";
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
    }
  });
  
  $conf->{parser}->register_commands(\@cmds);
}  

sub check_uri_detail {
  my ($self, $permsg) = @_;

  my $test = $permsg->{current_rule_name}; 
  my $rule = $permsg->{conf}->{uri_detail}->{$test};

  my %uri_detail = %{ $permsg->get_uri_detail_list() };

  while (my ($raw, $info) = each %uri_detail) {
    dbg("uri: running uri_detail $test: $raw");

    if (exists $rule->{raw}) {
      my($op,$patt,$neg) = @{$rule->{raw}};
      my $match = 0;
      if ( ($op eq '=~' && $raw =~ $patt) ||
           ($op eq '!~' && $raw !~ $patt) ) {
        $match = 1;
      }
      $match = 1-$match if $neg;
      next unless $match;
    }

    if (exists $rule->{type}) {
      next unless $info->{types};
      my($op,$patt,$neg) = @{$rule->{type}};
      my $match;
      for my $text (keys %{ $info->{types} }) {
        if ( ($op eq '=~' && $text =~ $patt) ||
             ($op eq '!~' && $text !~ $patt) ) { $match = $text; last }
      }
      if ( $neg ) {
        next if defined $match;
        dbg("uri: type negative matched: %s /%s/", $op,$patt);
      } else {
        next unless defined $match;
        dbg("uri: type matched: '%s' %s /%s/", $match,$op,$patt);
      }
    }

    if (exists $rule->{cleaned}) {
      next unless $info->{cleaned};
      my($op,$patt,$neg) = @{$rule->{cleaned}};
      my $match;
      for my $text (@{ $info->{cleaned} }) {
        if ( ($op eq '=~' && $text =~ $patt) ||
             ($op eq '!~' && $text !~ $patt) ) { $match = $text; last }
      }
      if ( $neg ) {
        next if defined $match;
        dbg("uri: cleaned negative matched: %s /%s/", $op,$patt);
      } else {
        next unless defined $match;
        dbg("uri: cleaned matched: '%s' %s /%s/", $match,$op,$patt);
      }
    }

    if (exists $rule->{text}) {
      next unless $info->{anchor_text};
      my($op,$patt,$neg) = @{$rule->{text}};
      my $match;
      for my $text (@{ $info->{anchor_text} }) {
        if ( ($op eq '=~' && $text =~ $patt) ||
             ($op eq '!~' && $text !~ $patt) ) { $match = $text; last }
      }
      if ( $neg ) {
        next if defined $match;
        dbg("uri: text negative matched: %s /%s/", $op,$patt);
      } else {
        next unless defined $match;
        dbg("uri: text matched: '%s' %s /%s/", $match,$op,$patt);
      }
    }

    if (exists $rule->{domain}) {
      next unless $info->{domains};
      my($op,$patt,$neg) = @{$rule->{domain}};
      my $match;
      for my $text (keys %{ $info->{domains} }) {
        if ( ($op eq '=~' && $text =~ $patt) ||
             ($op eq '!~' && $text !~ $patt) ) { $match = $text; last }
      }
      if ( $neg ) {
        next if defined $match;
        dbg("uri: domain negative matched: %s /%s/", $op,$patt);
      } else {
        next unless defined $match;
        dbg("uri: domain matched: '%s' %s /%s/", $match,$op,$patt);
      }
    }

    if (exists $rule->{host}) {
      next unless $info->{hosts};
      my($op,$patt,$neg) = @{$rule->{host}};
      my $match;
      for my $text (keys %{ $info->{hosts} }) {
        if ( ($op eq '=~' && $text =~ $patt) ||
             ($op eq '!~' && $text !~ $patt) ) { $match = $text; last }
      }
      if ( $neg ) {
        next if defined $match;
        dbg("uri: host negative matched: %s /%s/", $op,$patt);
      } else {
        next unless defined $match;
        dbg("uri: host matched: '%s' %s /%s/", $match, $op, $patt);
      }
    }

    dbg("uri: all criteria for $test met - HIT");
    return 1;
  }

  return 0;
}

# ---------------------------------------------------------------------------

sub has_host_key { 1 } # can match with "host" key

sub has_uridetail_negate { 1 } # Negating matches (Bug 8283)

1;
