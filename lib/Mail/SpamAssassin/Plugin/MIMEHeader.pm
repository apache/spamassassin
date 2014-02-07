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

=back

=cut

package Mail::SpamAssassin::Plugin::MIMEHeader;

use strict;
use warnings;
use bytes;
use re 'taint';

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Conf;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Util qw(untaint_var);

use vars qw(@ISA @TEMPORARY_METHODS);
@ISA = qw(Mail::SpamAssassin::Plugin);

@TEMPORARY_METHODS = (); 

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
      local ($1,$2,$3,$4);
      if ($value !~ /^(\S+)\s+(\S+)\s*([\=\!]\~)\s*(.+)$/) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }

      # provide stricter syntax for rule name!?
      my $rulename = untaint_var($1);
      my $hdrname = $2;
      my $negated = ($3 eq '!~') ? 1 : 0;
      my $pattern = $4;

      return unless $self->{parser}->is_delimited_regexp_valid($rulename, $pattern);

      $pattern = Mail::SpamAssassin::Util::make_qr($pattern);
      return $Mail::SpamAssassin::Conf::INVALID_VALUE unless $pattern;

      $self->{mimeheader_tests}->{$rulename} = {
        hdr => $hdrname,
        negated => $negated,
        if_unset => '',             # TODO!
        pattern => $pattern
      };

      # now here's a hack; generate a fake eval rule function to
      # call this rule's _real_ code!
      # TODO: we should have a more elegant way for new rule types to
      # be defined
      my $evalfn = "_mimeheader_eval_$rulename";
      $evalfn =~ s/[^a-zA-Z0-9_]/_/gs;

      # don't redefine the subroutine if it already exists!
      # this causes lots of annoying warnings and such during things like
      # "make test".
      return if (defined &{'Mail::SpamAssassin::Plugin::MIMEHeader::'.$evalfn});

      $self->{parser}->add_test($rulename, $evalfn."()",
                $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);

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
  my ($pobj, $scanner, $rulename) = @_;

  my $rule = $scanner->{conf}->{mimeheader_tests}->{$rulename};
  my $hdr = $rule->{hdr};
  my $negated = $rule->{negated};
  my $if_unset = $rule->{if_unset};
  my $pattern = $rule->{pattern};


  my $getraw;
  if ($hdr =~ s/:raw$//i) {
    $getraw = 1;
  } else {
    $getraw = 0;
  }

  foreach my $p ($scanner->{msg}->find_parts(qr/./)) {
    my $val;
    if ($getraw) {
      $val = $p->raw_header($hdr);
    } else {
      $val = $p->get_header($hdr);
    }
    $val ||= $if_unset;

    if ($val =~ ${pattern}) {
      return ($negated ? 0 : 1);
    }
  }

  return ($negated ? 1 : 0);
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

1;
