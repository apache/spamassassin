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

Mail::SpamAssassin::Handler::JavaScript - A MIME-part handler for C<text/javascript> parts

=head1 SYNOPSIS

  loadhandler  Mail::SpamAssassin::Handler::JavaScript

  script  RULE_NAME  /pattern/modifiers
  script  RULE_NAME  eval:check_script_contains_recip_addr()

=head1 DESCRIPTION

A MIME-part handler for C<text/javascript> parts. As it consumes each JavaScript
part: it collects the script text for C<script> rules (see L</SCRIPT RULES>) and
adds any navigation/redirect URLs it finds (e.g. C<< window.location = '...' >>)
to the URI detail list with type C<script>, so C<uri-detail> rules can target them.

=head1 RETURNS

This handler returns no sub-parts (always an empty list).

=head1 SCRIPT RULES

  script  RULENAME  /regex/modifiers
  score   RULENAME  1.0
  describe RULENAME  message contains script matching /regex/

These rules behave like C<rawbody> rules and support the C<multiple> and
C<maxhits=N> tflags.  By default a rule stops at its first match.  A rule may
also reference an eval function:

  script  RULENAME  eval:check_script_contains_recip_addr()

=head1 EVAL RULES

  check_script_contains_recip_addr()

    Fires if the recipient's address (To:addr) appears anywhere in the
    script text -- a common phishing indicator.

=cut

package Mail::SpamAssassin::Handler::JavaScript;

use strict;
use warnings;
use re 'taint';

use Mail::SpamAssassin::Handler;
use Mail::SpamAssassin::Logger qw(dbg would_log);
use Mail::SpamAssassin::Util qw(compile_regexp untaint_var);

our @ISA = qw(Mail::SpamAssassin::Handler);

sub log_dbg { Mail::SpamAssassin::Logger::dbg ("javascript: @_"); }

sub new {
  my ($class, $mailsaobject) = @_;
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->register_eval_rule("check_script_contains_recip_addr",
                            $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);

  # Register as the handler for JavaScript parts.  text/javascript is the
  # canonical type; the application/javascript et al. aliases and the .js
  # filename map to it via Message::Node::effective_type (see Node.pm).
  $self->register_handler('text/javascript', 'handle_javascript');

  $self->set_config($mailsaobject->{conf});

  return $self;
}

sub set_config {
  my ($self, $conf) = @_;
  my @cmds;

  push (@cmds, (
    {
      # script RULENAME /pattern/modifiers   (or  script RULENAME eval:func())
      # Define a rule that matches against collected JavaScript.  Regex rules are
      # compiled and stored; the match loop is built in finish_parsing_end.  An
      # eval: form just registers the named eval rule.
      setting => 'script',
      is_priv => 1,
      type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
      code => sub {
        my ($self, $key, $value, $line) = @_;

        if ($value !~ /^(\S+)\s+(.+)$/) {
          return $Mail::SpamAssassin::Conf::INVALID_VALUE;
        }
        my ($name, $pattern) = ($1, $2);

        if ( $pattern =~ /^eval:(.*)/ ) {
          $self->{parser}->add_test($name, $1,
            $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
          return;
        }

        my ($re, $err) = compile_regexp($pattern, 1);
        if (!$re) {
          dbg("javascript: invalid script regexp for $name '$pattern': $err");
          return $Mail::SpamAssassin::Conf::INVALID_VALUE;
        }

        $conf->{script_rules}->{$name} = $re;
        $self->{parser}->add_test($name, undef,
          $Mail::SpamAssassin::Conf::TYPE_EMPTY_TESTS);
      },
    },
  ));

  $conf->{parser}->register_commands(\@cmds);
}

# handle_javascript($node, $pms): collect one part's JavaScript onto
# $pms->{Handler}{JavaScript}{script_text} (one entry per part, document order),
# and add any redirect URLs it navigates to (window.location = '...', etc.) to the
# URI detail list.  Produces no child parts.
sub handle_javascript {
  my ($self, $node, $pms) = @_;

  my $js = $node->decode();
  return [] unless defined $js && length $js;

  push @{ $pms->{Handler}{JavaScript}{script_text} }, $js;
  log_dbg("collected ".length($js)." bytes of script from ".($node->{name} || $node->{type} || '?'));

  $self->_extract_uris($js, $pms);

  return [];
}

# Pull navigation/redirect URLs out of script text and add them to the URI detail
# list (tagged 'script').  A URL assigned to the browser location -- e.g.
# window.location='https://...', location.href="https://...",
# location.replace('https://...') -- is the page the script sends the victim to,
# but it lives inside a JS string, so the HTML/SVG link-attribute scanners never
# see it.  Surfacing it lets uri-detail rules target it:
#
#   uri-detail RULENAME  type =~ /script/  raw =~ /badsite\.example/
#
# We deliberately match only location-navigation forms (not every http(s) string
# in the script) to keep noise -- analytics beacons, commented URLs, library CDN
# references -- out of the URI list.
sub _extract_uris {
  my ($self, $js, $pms) = @_;

  my %seen;
  # (window|top|self|parent|document)?.location  followed by either an
  # assignment (= 'url' / .href = 'url') or a navigation call
  # (.replace('url') / .assign('url')), capturing the quoted http(s) URL.
  while ( $js =~ m{
        (?: \b (?: window | top | self | parent | document ) \s* \. \s* )?
        location
        \s*
        (?:
            (?: \. \s* href \s* )? = |          # location = / location.href =
            \. \s* (?: replace | assign ) \s* \(  # location.replace( / .assign(
        )
        \s* (['"]) ( https? :// [^'"]+ ) \1
      }gixs ) {
    my $uri = $2;
    next if $seen{$uri}++;
    log_dbg("found redirect URI: $uri");
    $pms->add_uri_detail_list($uri, { script => 1 }, 'JavaScript');
  }
}

# After config is fully parsed, compile all script rules into a single sub
# (_run_script_rules), mirroring how the PDF/Image handlers build their custom
# rule types.  Each default rule stops at its first hit; "multiple" rules scan
# with /g and honour maxhits=N.
sub finish_parsing_end {
  my ($self, $opts) = @_;
  my $conf = $opts->{conf};

  return unless exists $conf->{script_rules};

  my $would_log = would_log('dbg');

  my $eval = <<'EOF';
package Mail::SpamAssassin::Handler::JavaScript;

sub _run_script_rules {
    my ($self, $opts) = @_;
    my $pms = $opts->{permsgstatus};
    my ($test_qr, $hits);

    my $script_text = $self->_get_script_text($pms);
    return unless @$script_text;

EOF

  my $loopid = 0;
  foreach my $name (keys %{$conf->{script_rules}}) {
    $loopid++;
    my $tflags = $conf->{tflags}->{$name} || '';

    my ($dbg_running_rule, $dbg_ran_rule) = ('', '');
    if ($would_log) {
      $dbg_running_rule = qq(dbg("running rule $name"););
      $dbg_ran_rule = qq(dbg(qq(ran rule $name ======> got hit "\$match")););
    }

    my $ifwhile   = 'if';
    my $last      = 'last;';
    my $modifiers = 'p';
    my $init_hits = '';

    if ($tflags =~ /\bmultiple\b/) {
      $ifwhile = 'while';
      $modifiers .= 'g';
      if ($tflags =~ /\bmaxhits=(\d+)\b/) {
        $init_hits = "\$hits = 0;";
        $last = "last rule_$loopid if ++\$hits >= $1;";
      } else {
        $last = '';
      }
    }

    $eval .= <<"EOF";
    $dbg_running_rule
    \$test_qr = \$pms->{conf}->{script_rules}->{$name};
    $init_hits
    rule_$loopid: foreach my \$line (\@\$script_text) {
        $ifwhile ( \$line =~ /\$test_qr/$modifiers ) {
            my \$match = defined \${^MATCH} ? \${^MATCH} : '<negative match>';
            $dbg_ran_rule
            \$pms->got_hit('$name', 'SCRIPT: ', 'ruletype' => 'rawbody');
            $last
        }
    }
EOF
  }

  $eval .= "}\n";

  # The generated sub replaces the no-op _run_script_rules placeholder below.
  no warnings 'redefine';
  eval untaint_var($eval);
  if ($@) {
    die("javascript: error compiling script rules: $@");
  }
}

# Real implementation is compiled in by finish_parsing_end; this is the no-op
# used when no script rules are configured.
sub _run_script_rules { }

sub parsed_metadata {
  my ($self, $opts) = @_;
  $self->_run_script_rules($opts);
}

# The text source for script rules and the eval rule: the per-part script text
# collected by handle_javascript (in document order).
sub _get_script_text {
  my ($self, $pms) = @_;
  return ($pms->{Handler}{JavaScript} && $pms->{Handler}{JavaScript}{script_text}) || [];
}

# Eval rule: true if the recipient address appears in any collected script text.
sub check_script_contains_recip_addr {
  my ($self, $pms) = @_;

  my $to = $pms->get('To:addr');
  return 0 unless defined $to && length $to;

  my $script_text = $self->_get_script_text($pms);
  return scalar grep { /\Q$to\E/ } @$script_text;
}

# Characters that separate tokens in JavaScript: statement/expression
# punctuation, whitespace, quotes, and operators.  A run of anything NOT in this
# set is one "token".
my $JS_SEPARATORS = qr/[;,(){}\[\]\s"'=:?+\-*\/<>&|!.~^%@`]+/;

1;
