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

Mail::SpamAssassin::Plugin::MainBody - match rules against the inline message body only

=head1 SYNOPSIS

  loadplugin Mail::SpamAssassin::Plugin::MainBody

  main_body  RULE_NAME   /pattern/modifiers
  describe   RULE_NAME   Description of the rule
  score      RULE_NAME   1.0

=head1 DESCRIPTION

This plugin adds a new C<main_body> rule type.  A C<main_body> rule works just
like a C<body> rule, but instead of matching against the rendered text of every
body part of a message, it matches only against the "main" body -- the rendered
text of the inline body parts, excluding attachments.

The body parts that make up the main body are selected as follows:

=over 4

=item *

Attachments (any part with a filename) are skipped.

=item *

For a C<multipart/alternative> section, the one part named by the
C<multipart_alternative_preferred_part> configuration setting is used.  When
that setting is unset, C<text/html> is preferred, falling back to C<text/plain>.

=item *

Other multipart containers (for example C<multipart/mixed>) are descended into,
and every inline text part they contain is included, in display order.  Any
other leaf type is skipped.

=back

When more than one part contributes, their text is concatenated in display order.

Note that, as for C<body> rules, the text is the full rendered text of each
part, including any text that would not be visible in a mail client.

As with C<body> rules, the message Subject header is prepended as the first line
of the text and the same whitespace normalization is applied.

=head1 RULE DEFINITION

    main_body  RULE_NAME   /pattern/modifiers

C<pattern> is a Perl regular expression, exactly as for a C<body> rule.  C<eval:>
patterns are not supported.

=head1 TFLAGS

This plugin supports the following C<tflags>:

=over 4

=item nosubject

By default the message Subject header is considered part of the body and becomes
the first line when running the rules.  If you don't want to match Subject along
with body text, use C<tflags RULENAME nosubject>.

=item multiple

The test will be evaluated multiple times, for use with meta rules.

=item maxhits=N

If C<multiple> is specified, limit the number of hits found to N.

=back

=head1 AUTHORS

Kent Oyer <kent@mxguardian.net>

=cut

package Mail::SpamAssassin::Plugin::MainBody;

use strict;
use warnings;
use re 'taint';

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger qw(would_log);
use Mail::SpamAssassin::Util qw(compile_regexp untaint_var);

our @ISA = qw(Mail::SpamAssassin::Plugin);

# constructor
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->set_config($mailsaobject->{conf});

  return $self;
}

sub dbg { Mail::SpamAssassin::Logger::dbg("MainBody: @_"); }

sub set_config {
  my ($self, $conf) = @_;
  my @cmds;

  push (@cmds, {
    setting => 'main_body',
    is_priv => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;

      if ($value !~ /^(\S+)\s+(.+)$/) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      my $name = $1;
      my $pattern = $2;

      # eval: rules are not supported for main_body
      if ($pattern =~ /^eval:/) {
        dbg("eval rules are not supported for main_body ($name)");
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }

      my ($re, $err) = compile_regexp($pattern, 1);
      if (!$re) {
        dbg("invalid regexp for $name '$pattern': $err");
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }

      $conf->{parser}->{conf}->{main_body_rules}->{$name} = $re;

      # just define the test so that scores, describe and lint work
      $self->{parser}->add_test($name, undef,
        $Mail::SpamAssassin::Conf::TYPE_EMPTY_TESTS);
    }
  });

  $conf->{parser}->register_commands(\@cmds);
}

sub finish_parsing_end {
  my ($self, $opts) = @_;
  my $conf = $opts->{conf};

  # only compile rules if we have any
  return unless exists $conf->{main_body_rules};

  # check if we should include calls to dbg()
  my $would_log = would_log('dbg');

  # build eval string
  my $eval = <<'EOF';
package Mail::SpamAssassin::Plugin::MainBody;

sub _run_main_body_rules {
    my ($self, $opts) = @_;
    my $pms = $opts->{permsgstatus};
    my ($test_qr,$hits,$nosubj);

    # get the main body text
    my $main_body = $self->_get_main_body($pms);

    # check all main_body rules
EOF

  my $loopid = 0;
  foreach my $name (keys %{$conf->{main_body_rules}}) {
    $loopid++;
    my $tflags = $conf->{tflags}->{$name} || '';
    my $score = $conf->{scores}->{$name} || 1;

    my $dbg_running_rule = '';
    my $dbg_ran_rule = '';
    if ($would_log) {
      $dbg_running_rule = qq(dbg("running rule $name"););
      $dbg_ran_rule = qq(dbg(qq(ran rule $name ======> got hit "\$match")););
    }

    my $ifwhile = 'if';
    my $last = 'last;';
    my $modifiers = 'p';
    my $init_hits = '';
    # Reset the match position per line.  Required for 'multiple' matches so a
    # preceding rule's leftover pos() (e.g. one that stopped early on maxhits)
    # does not make this rule resume mid-line and miss earlier matches.
    my $reset_pos = '';

    if ($tflags =~ /\bmultiple\b/) {
      $ifwhile = 'while';
      $modifiers .= 'g';
      $reset_pos = 'pos $line = 0;';
      if ($tflags =~ /\bmaxhits=(\d+)\b/) {
        $init_hits = "\$hits = 0;";
        $last = "last rule_$loopid if ++\$hits >= $1;";
      } else {
        $last = '';
      }
    }

    my $init_subject = '';
    my $skip_subject = '';

    if ($tflags =~ /\bnosubject\b/) {
      $init_subject = '$nosubj = 1;';
      $skip_subject = 'if ($nosubj) { $nosubj = 0; next; }';
    }

    $eval .= <<"EOF";
    $dbg_running_rule
    \$test_qr = \$pms->{conf}->{main_body_rules}->{$name};
    $init_hits
    $init_subject
    rule_$loopid: foreach my \$line (\@\$main_body) {
        $skip_subject
        $reset_pos
        $ifwhile ( \$line =~ /\$test_qr/$modifiers ) {
            my \$match = defined \${^MATCH} ? \${^MATCH} : '<negative match>';
            $dbg_ran_rule
            \$pms->{pattern_hits}->{$name} = \$match;
            \$pms->got_hit('$name','MAINBODY: ','ruletype' => 'body', 'score' => $score);
            $last
        }
    }
EOF

  }
  $eval .= <<'EOF';
}

EOF

  # compile the new rules
  eval untaint_var($eval);
  if ($@) {
    die("MainBody: Error compiling rules: $@");
  }
}

sub _run_main_body_rules {
  # placeholder, replaced by the compiled rules above
}

sub parsed_metadata {
  my ($self, $opts) = @_;

  $self->_run_main_body_rules($opts);
}

#
# Get the main body of the message as an array of lines
#
sub _get_main_body {
  my ($self, $pms) = @_;

  if (exists $pms->{main_body}) {
    return $pms->{main_body};
  }

  return $pms->{main_body} = $pms->get_message()->get_main_body_text_array();
}

1;
