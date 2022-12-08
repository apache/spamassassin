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

MIMEHeader - perform regexp tests against MIME headers

=head1 SYNOPSIS

  loadplugin    Mail::SpamAssassin::Plugin::MIMEHeader
  mimeheader	NAME_OF_RULE    Content-Id =~ /foo/

=head1 DESCRIPTION

This plugin allows regexp rules to be written against MIME headers in the
message.

=head1 RULE DEFINITIONS AND PRIVILEGED SETTINGS

=over 4

=item mimeheader NAME_OF_RULE Header-Name =~ /pattern/modifiers

Specify a rule.  C<NAME_OF_RULE> is the name of the rule to be used,
C<Header-Name> is the name of the MIME header to check, and
C</pattern/modifiers> is the Perl regular expression to match against this.

Note that in a message of multiple parts, each header will be checked
against the pattern separately.  In other words, if multiple parts
have a 'Content-Type' header, each header's value will be tested
individually as a separate string.

Header names are considered case-insensitive.

The header values are normally cleaned up a little; for example, whitespace
around the newline character in "folded" headers will be replaced with a single
space.  Append C<:raw> to the header name to retrieve the raw, undecoded value,
including pristine whitespace, instead.

=item tflags NAME_OF_RULE range=x-y

Match only from specific MIME parts, indexed in the order they are parsed.
Part 1 = main message headers. Part 2 = next part etc.

 range=1    (match only main headers, not any subparts)
 range=2-   (match any subparts, but not the main headers)
 range=-3   (match only first three parts, including main headers)
 range=2-3  (match only first two subparts)

=item tflags NAME_OF_RULE concat

Concatenate all headers from all mime parts (possible range applied) into a
single string for matching.  This allows matching headers across multiple
parts with single regex.  Normally pattern is tested individually for
different mime parts.

=back

=cut

package Mail::SpamAssassin::Plugin::MIMEHeader;

use strict;
use warnings;
# use bytes;
use re 'taint';

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Conf;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Util qw(untaint_var compile_regexp);
use Mail::SpamAssassin::Constants qw(:sa);

our @ISA = qw(Mail::SpamAssassin::Plugin);

our @TEMPORARY_METHODS;

my $RULENAME_RE = RULENAME_RE;

# ---------------------------------------------------------------------------

# constructor
sub new {
  my $class = shift;
  my $samain = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($samain);
  bless ($self, $class);

  $self->set_config($samain->{conf});

  return $self;
}

# ---------------------------------------------------------------------------

sub set_config {
  my($self, $conf) = @_;
  my @cmds;

  my $pluginobj = $self;        # allow use inside the closure below

  push (@cmds, {
    setting => 'mimeheader',
    is_priv => 1,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      local ($1,$2,$3);
      if ($value !~ s/^(${RULENAME_RE})\s+//) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      my $rulename = untaint_var($1);
      if ($value eq '') {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      # Take :raw to hdrname!
      if ($value !~ /^([^:\s]+(?:\:(?:raw)?)?)\s*([=!]~)\s*(.+)$/) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      my $hdrname = $1;
      my $negated = $2 eq '!~' ? 1 : 0;
      my $pattern = $3;
      $hdrname =~ s/:$//;
      my $if_unset = '';
      if ($pattern =~ s/\s+\[if-unset:\s+(.+)\]$//) {
         $if_unset = $1;
      }
      my ($rec, $err) = compile_regexp($pattern, 1);
      if (!$rec) {
        info("mimeheader: invalid regexp for $rulename '$pattern': $err");
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }

      $self->{mimeheader_tests}->{$rulename} = {
        hdr => $hdrname,
        negated => $negated,
        if_unset => $if_unset,
        pattern => $rec
      };

      # now here's a hack; generate a fake eval rule function to
      # call this rule's _real_ code!
      # TODO: we should have a more elegant way for new rule types to
      # be defined
      my $evalfn = "_mimeheader_eval_$rulename";

      # don't redefine the subroutine if it already exists!
      # this causes lots of annoying warnings and such during things like
      # "make test".
      return if (defined &{'Mail::SpamAssassin::Plugin::MIMEHeader::'.$evalfn});

      $self->{parser}->add_test($rulename, $evalfn."()",
                $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);

      # Support named regex captures
      $self->{parser}->parse_captures($rulename, $rec);

      # evalfn/rulename safe, sanitized by $RULENAME_RE
      my $evalcode = '
        sub Mail::SpamAssassin::Plugin::MIMEHeader::'.$evalfn.' {
          $_[0]->eval_hook_called($_[1], q{'.$rulename.'});
        }
      ';

      eval
        $evalcode . '; 1'
      or do {
        my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
        warn "mimeheader: plugin error: $eval_stat\n";
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      };

      $pluginobj->register_eval_rule($evalfn);

      push @TEMPORARY_METHODS, "Mail::SpamAssassin::Plugin::MIMEHeader::${evalfn}";
    }
  });

  $conf->{parser}->register_commands(\@cmds);
}

# ---------------------------------------------------------------------------

sub eval_hook_called {
  my ($pobj, $pms, $rulename) = @_;

  my $conf = $pms->{conf};
  my $rule = $conf->{mimeheader_tests}->{$rulename};
  my $hdr = $rule->{hdr};
  my $negated = $rule->{negated};
  my $pattern = $rule->{pattern};
  my $tflags = $conf->{tflags}->{$rulename}||'';
  
  my $getraw = 0;
  if ($hdr =~ s/:raw$//) {
    $getraw = 1;
  }

  my $range_min = 0;
  my $range_max = 1000;
  if ($tflags =~ /(?:^|\s)range=(\d+)?(-)?(\d+)?(?:\s|$)/) {
    if (defined $1 && defined $2 && defined $3) {
      $range_min = $1;
      $range_max = $3;
    }
    elsif (defined $1 && defined $2) {
      $range_min = $1;
    }
    elsif (defined $2 && defined $3) {
      $range_max = $3;
    }
    elsif (defined $1) {
      $range_min = $range_max = $1;
    }
  }

  my $multiple = $tflags =~ /\bmultiple\b/;
  my $concat = $tflags =~ /\bconcat\b/;
  my $maxhits = $tflags =~ /\bmaxhits=(\d+)\b/ ? $1 :
                           $multiple ? 1000 : 1;
  my $cval = '';

  my $idx = 0;
  foreach my $p ($pms->{msg}->find_parts(qr/./)) {
    $idx++;
    last if $idx > $range_max;
    next if $idx < $range_min;

    my $val;
    if ($hdr eq 'ALL') {
      $val = $p->get_all_headers($getraw, 0);
    } elsif ($getraw) {
      $val = $p->raw_header($hdr);
    } else {
      $val = $p->get_header($hdr);
    }
    $val = $rule->{if_unset}  if !defined $val;

    if ($concat) {
      $val .= "\n" unless $val =~ /\n$/;
      $cval .= $val;
      next;
    }

    if (_check($pms, $rulename, $val, $pattern, $negated, $maxhits, "part $idx")) {
      return 0;
    }
  }

  if ($concat) {
    if (_check($pms, $rulename, $cval, $pattern, $negated, $maxhits, 'concat')) {
      return 0;
    }
  }

  if ($negated) {
    dbg("mimeheader: ran rule $rulename ======> got hit: \"<negative match>\"");
    return 1;
  }

  return 0;
}

sub _check {
  my ($pms, $rulename, $value, $pattern, $negated, $maxhits, $desc) = @_;

  my $hits = 0;
  my %captures;
  while ($value =~ /$pattern/gp) {
    last if $negated;
    if (%-) {
      foreach my $cname (keys %-) {
        push @{$captures{$cname}}, grep { $_ ne "" } @{$-{$cname}};
      }
    }
    my $match = defined ${^MATCH} ? ${^MATCH} : "<negative match>";
    $pms->got_hit($rulename, '', ruletype => 'eval');
    dbg("mimeheader: ran rule $rulename ======> got hit: \"$match\" ($desc)");
    last if ++$hits >= $maxhits;
  }
  $pms->set_captures(\%captures) if %captures;
  return $hits;
}

# ---------------------------------------------------------------------------

sub finish_tests {
  my ($self, $params) = @_;

  foreach my $method (@TEMPORARY_METHODS) {
    undef &{$method};
  }
  @TEMPORARY_METHODS = ();      # clear for next time
}

# ---------------------------------------------------------------------------

sub has_all_header { 1 } # Supports ALL header query (Bug 5582)
sub has_tflags_range { 1 } # Supports tflags range=x-y
sub has_tflags_concat { 1 } # Supports tflags concat
sub has_tflags_multiple { 1 } # Supports tflags multiple
sub has_capture_rules { 1 } # Supports named regex captures (Bug 7992)

1;
