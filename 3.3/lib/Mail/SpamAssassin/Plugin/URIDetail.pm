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

  uri_detail SYMBOLIC_TEST_NAME key1 =~ /value1/  key2 !~ /value2/ ...

Supported keys are:

C<raw> is the raw URI prior to any cleaning
(e.g. "http://spamassassin.apache%2Eorg/").

C<type> is the tag(s) which referenced the raw_uri.  I<parsed> is a
faked type which specifies that the raw_uri was parsed from the
rendered text.

C<cleaned> is a list including the raw URI and various cleaned
versions of the raw URI (http://spamassassin.apache%2Eorg/,
http://spamassassin.apache.org/).

C<text> is the anchor text(s) (text between <a> and </a>) that
linked to the raw URI.

C<domain> is the domain(s) found in the cleaned URIs.

Example rule for matching a URI where the raw URI matches "%2Ebar",
the domain "bar.com" is found, and the type is "a" (an anchor tag).

  uri_detail TEST1 raw =~ /%2Ebar/  domain =~ /^bar\.com$/  type =~ /^a$/

Example rule to look for suspicious "https" links:

  uri_detail FAKE_HTTPS text =~ /\bhttps:/  cleaned !~ /\bhttps:/

Regular expressions should be delimited by slashes.

=cut

package Mail::SpamAssassin::Plugin::URIDetail;
use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Util qw(untaint_var);

use strict;
use warnings;
use bytes;
use re 'taint';

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

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
      while ($def =~ m{\b(\w+)\b\s*([\=\!]\~)\s*((?:/.*?/|m(\W).*?\4)[imsx]*)(?=\s|$)}g) {
	my $target = $1;
	my $op = $2;
	my $pattern = $3;

	if ($target !~ /^(?:raw|type|cleaned|text|domain)$/) {
	    return $Mail::SpamAssassin::Conf::INVALID_VALUE;
	}
	if ($conf->{parser}->is_delimited_regexp_valid($name, $pattern)) {
	    $pattern = $pluginobj->make_qr($pattern);
	}
	else {
	    return $Mail::SpamAssassin::Conf::INVALID_VALUE;
	}

	dbg("config: uri_detail adding ($target $op /$pattern/) to $name");
        $conf->{parser}->{conf}->{uri_detail}->{$name}->{$target} =
          [$op, $pattern];
	$added_criteria = 1;
      }

      if ($added_criteria) {
	dbg("config: uri_detail added $name\n");
	$conf->{parser}->add_test($name, 'check_uri_detail()', $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
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

  my %uri_detail = %{ $permsg->get_uri_detail_list() };

  while (my ($raw, $info) = each %uri_detail) {
    my $test = $permsg->{current_rule_name}; 

    dbg("uri: running $test\n");

    my $rule = $permsg->{conf}->{uri_detail}->{$test};

    if (exists $rule->{raw}) {
      my($op,$patt) = @{$rule->{raw}};
      if ( ($op eq '=~' && $raw =~ /$patt/) ||
           ($op eq '!~' && $raw !~ /$patt/) ) {
        dbg("uri: raw matched: '%s' %s /%s/", $raw,$op,$patt);
      } else {
        next;
      }
    }

    if (exists $rule->{type}) {
      next unless $info->{types};
      my($op,$patt) = @{$rule->{type}};
      my $match;
      for my $text (keys %{ $info->{types} }) {
        if ( ($op eq '=~' && $text =~ /$patt/) ||
             ($op eq '!~' && $text !~ /$patt/) ) { $match = $text; last }
      }
      next unless defined $match;
      dbg("uri: type matched: '%s' %s /%s/", $match,$op,$patt);
    }

    if (exists $rule->{cleaned}) {
      next unless $info->{cleaned};
      my($op,$patt) = @{$rule->{cleaned}};
      my $match;
      for my $text (@{ $info->{cleaned} }) {
        if ( ($op eq '=~' && $text =~ /$patt/) ||
             ($op eq '!~' && $text !~ /$patt/) ) { $match = $text; last }
      }
      next unless defined $match;
      dbg("uri: cleaned matched: '%s' %s /%s/", $match,$op,$patt);
    }

    if (exists $rule->{text}) {
      next unless $info->{anchor_text};
      my($op,$patt) = @{$rule->{text}};
      my $match;
      for my $text (@{ $info->{anchor_text} }) {
        if ( ($op eq '=~' && $text =~ /$patt/) ||
             ($op eq '!~' && $text !~ /$patt/) ) { $match = $text; last }
      }
      next unless defined $match;
      dbg("uri: text matched: '%s' %s /%s/", $match,$op,$patt);
    }

    if (exists $rule->{domain}) {
      next unless $info->{domains};
      my($op,$patt) = @{$rule->{domain}};
      my $match;
      for my $text (keys %{ $info->{domains} }) {
        if ( ($op eq '=~' && $text =~ /$patt/) ||
             ($op eq '!~' && $text !~ /$patt/) ) { $match = $text; last }
      }
      next unless defined $match;
      dbg("uri: domain matched: '%s' %s /%s/", $match,$op,$patt);
    }

    if (would_log('dbg', 'rules') > 1) {
      dbg("uri: criteria for $test met");
    }
    
    $permsg->got_hit($test);

    # reset hash
    keys %uri_detail;

    return 0;
  }

  return 0;
}

# ---------------------------------------------------------------------------

# turn "/foobar/i" into qr/(?i)foobar/
sub make_qr {
  my ($self, $pattern) = @_;

  my $re_delim;
  if ($pattern =~ s/^m(\W)//) {     # m!foo/bar!
    $re_delim = $1;
  } else {                          # /foo\/bar/ or !foo/bar!
    $pattern =~ s/^(\W)//; $re_delim = $1;
  }
  if (!$re_delim) {
    return;
  }

  $pattern =~ s/${re_delim}([imsx]*)$//;

  my $mods = $1;
  if ($mods) { $pattern = "(?".$mods.")".$pattern; }

  return qr/$pattern/;
}

# ---------------------------------------------------------------------------

1;
