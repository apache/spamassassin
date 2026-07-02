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

Mail::SpamAssassin::Handler::SVG - A MIME-part handler for C<image/svg+xml> parts

=head1 SYNOPSIS

  loadhandler  Mail::SpamAssassin::Handler::SVG

  svgtext  RULE_NAME  /pattern/modifiers

  body  SVG_TEXT_HEAVY  eval:check_svg_text_ratio('5')

=head1 DESCRIPTION

SVG is increasingly used as a phishing vector: an image file that is really a
text/link canvas, often carrying embedded JavaScript.  This handler parses each
SVG part and exposes its B<text> content to C<svgtext> rules -- kept separate
from HTML body text so the same word (e.g. "docusign") can be scored differently
in an SVG than in ordinary HTML.

Links found in the SVG are added to the URI detail list (type C<svg>), and any
embedded JavaScript is surfaced for the JavaScript handler -- see L</RETURNS>.
An SVG whose ratio of text words to graphics elements is high -- a mostly-text
"image" -- is flagged via the C<check_svg_text_ratio()> eval rule (see
L</EVAL RULES>).

=head1 RETURNS

The handler returns any embedded JavaScript found in the SVG as a single
C<< { type => 'text/javascript', data => $bytes } >> sub-part, which the handler
framework dispatches to the JavaScript handler
(L<Mail::SpamAssassin::Handler::JavaScript>).  The script bodies of C<< <script> >>
elements, C<javascript:> URIs, and C<on*> event-handler attributes are joined
into that one part.  When the SVG contains no script, the handler returns an
empty list.

=head1 SVG TEXT RULES

  svgtext  RULENAME  /regex/modifiers
  score    RULENAME  1.0
  describe RULENAME  SVG contains text matching /regex/

These rules behave like C<rawbody> rules and support the C<multiple> and
C<maxhits=N> tflags.

=head1 EVAL RULES

  check_svg_text_ratio(MIN_RATIO)

    Fires if any SVG part's ratio of text words to graphics elements
    (image/path/rect/circle/ellipse/line/polyline/polygon/use) is greater than
    or equal to MIN_RATIO.  An SVG that contains text words but no graphics
    element at all is treated as having an infinite ratio and always fires.
    MIN_RATIO defaults to 1.

=cut

package Mail::SpamAssassin::Handler::SVG;

use strict;
use warnings;
use re 'taint';

use HTML::Parser ();
use Mail::SpamAssassin::Handler;
use Mail::SpamAssassin::Logger qw(dbg info would_log);
use Mail::SpamAssassin::Util qw(compile_regexp untaint_var);

our @ISA = qw(Mail::SpamAssassin::Handler);

sub log_dbg { Mail::SpamAssassin::Logger::dbg ("svg: @_"); }

# SVG graphics elements -- presence of any of these means the SVG actually
# renders something other than text/links.
my %graphics_tags = map { $_ => 1 } qw(
  image path rect circle ellipse line polyline polygon use
);

sub new {
  my ($class, $mailsaobject) = @_;
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->register_eval_rule("check_svg_text_ratio",
                            $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);

  $self->register_handler('image/svg+xml', 'handle_svg');

  $self->set_config($mailsaobject->{conf});

  return $self;
}

sub set_config {
  my ($self, $conf) = @_;
  my @cmds;

  push (@cmds, (
    {
      # svgtext RULENAME /pattern/modifiers  (or  svgtext RULENAME eval:func())
      setting => 'svgtext',
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
          dbg("svg: invalid svgtext regexp for $name '$pattern': $err");
          return $Mail::SpamAssassin::Conf::INVALID_VALUE;
        }

        $conf->{svgtext_rules}->{$name} = $re;
        $self->{parser}->add_test($name, undef,
          $Mail::SpamAssassin::Conf::TYPE_EMPTY_TESTS);
      },
    },
  ));

  $conf->{parser}->register_commands(\@cmds);
}

# handle_svg($node, $pms): parse one SVG part.  Collect text into
# $pms->{Handler}{SVG}{text}; add any http(s) links to the URI detail list (type
# 'svg'); accumulate the text-word and graphics-element counts across all parts
# (for check_svg_text_ratio); and return any embedded script as a text/javascript
# sub-part.
sub handle_svg {
  my ($self, $node, $pms) = @_;

  my $data = $node->decode();
  return [] unless defined $data && length $data;

  my ($text, $script, $uris, $graphics_count) = $self->_parse_svg($data);

  push @{ $pms->{Handler}{SVG}{text} }, @$text if @$text;

  # Add links found in the SVG to the URI detail list, tagged 'svg' (so rules can
  # target links that hide inside an "image") plus the source element name (e.g.
  # 'a' for a clickable link, 'image' for an external image reference).
  for my $u ( @$uris ) {
    my ($uri, $tag) = @$u;
    log_dbg("found URI ($tag): $uri");
    $pms->add_uri_detail_list($uri, { svg => 1, $tag => 1 }, 'SVG');
  }

  # Accumulate text-word and graphics-element counts across all SVG parts.  A
  # mostly-text "image" (many words, few or no graphics elements) is a likely
  # text-phishing canvas -- see check_svg_text_ratio().
  my $word_count = 0;
  $word_count += () = $_ =~ /\S+/g for @$text;
  $pms->{Handler}{SVG}{word_count}     += $word_count;
  $pms->{Handler}{SVG}{graphics_count} += $graphics_count;
  log_dbg("SVG words=$word_count graphics=$graphics_count: ".($node->{name} || '?'));

  return [] unless @$script;
  my $js = join("\n", grep { defined && length } @$script);
  return [] unless length $js;
  return [ { type => 'text/javascript', data => $js } ];
}

# Run the SVG through HTML::Parser (lenient; never dies on malformed/hostile
# input, no XML entity-expansion attack surface) and pull out:
#   - text nodes (outside <script>)            -> @text
#   - <script> text + javascript:/on* attrs    -> @script
#   - http(s) URIs from link/ref attributes    -> @uris ([uri, source-tag] pairs)
#   - number of graphics elements seen         -> $graphics_count
sub _parse_svg {
  my ($self, $data) = @_;

  my @text;
  my @script;
  my @uris;
  my $graphics_count = 0;
  my $in_script      = 0;

  my $p = HTML::Parser->new(
    api_version => 3,
    start_h => [ sub {
      my ($tag, $attr, $attrseq) = @_;
      my $lc = lc $tag;
      $in_script++ if $lc eq 'script';
      $graphics_count++ if $graphics_tags{$lc};

      for my $an (@$attrseq) {
        my $av = $attr->{$an};
        next unless defined $av;
        if ($an =~ /^on/i) {
          push @script, $av;
        }
        elsif ($av =~ /^javascript:(.*)/is) {
          push @script, $1;
        }
        # Link/reference attributes -- href, xlink:href (SVG's namespaced link),
        # src, action, data -- carrying an http(s) URI.  A clickable link in an
        # "image" is a strong phishing signal.  Keep the source tag so callers
        # can tell e.g. an <a> link from an image reference.  Normalise SVG's
        # <image> element to 'img' so rules match the HTML <img> tag name.
        elsif ($an =~ /^(?:xlink:)?(?:href|src|action|data)$/i
               && $av =~ m{^\s*https?://}i) {
          my $src_tag = $lc eq 'image' ? 'img' : $lc;
          push @uris, [ $av, $src_tag ];
        }
      }
    }, 'tagname, attr, attrseq' ],
    text_h => [ sub {
      my ($dtext) = @_;
      return unless defined $dtext;
      $dtext =~ s/^\s+|\s+$//g;
      return if $dtext eq '';
      if ($in_script > 0) {
        push @script, $dtext;
      } else {
        push @text, $dtext;
      }
    }, 'dtext' ],
    end_h => [ sub {
      my ($tag) = @_;
      $in_script-- if lc($tag) eq 'script' && $in_script > 0;
    }, 'tagname' ],
  );

  eval {
    local $SIG{__WARN__} = sub {
      my $err = $_[0];
      $err =~ s/\s+/ /gs; $err =~ s/(.*) at .*/$1/s;
      info("svg: HTML::Parser warning: $err");
    };
    $p->parse($data);
    # bug 7437: close any unclosed <script> so trailing text is not lost
    $p->parse("</script>") while $in_script > 0;
    $p->eof();
  };

  return (\@text, \@script, \@uris, $graphics_count);
}

# Compile svgtext rules into _run_svgtext_rules, mirroring the JS/PDF handlers.
sub finish_parsing_end {
  my ($self, $opts) = @_;
  my $conf = $opts->{conf};

  return unless exists $conf->{svgtext_rules};

  my $would_log = would_log('dbg');

  my $eval = <<'EOF';
package Mail::SpamAssassin::Handler::SVG;

sub _run_svgtext_rules {
    my ($self, $opts) = @_;
    my $pms = $opts->{permsgstatus};
    my ($test_qr, $hits);

    my $svg_text = $self->_get_svg_text($pms);
    return unless @$svg_text;

EOF

  my $loopid = 0;
  foreach my $name (keys %{$conf->{svgtext_rules}}) {
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
    \$test_qr = \$pms->{conf}->{svgtext_rules}->{$name};
    $init_hits
    rule_$loopid: foreach my \$line (\@\$svg_text) {
        $ifwhile ( \$line =~ /\$test_qr/$modifiers ) {
            my \$match = defined \${^MATCH} ? \${^MATCH} : '<negative match>';
            $dbg_ran_rule
            \$pms->got_hit('$name', 'SVG: ', 'ruletype' => 'rawbody');
            $last
        }
    }
EOF
  }

  $eval .= "}\n";

  no warnings 'redefine';
  eval untaint_var($eval);
  if ($@) {
    die("svg: error compiling svgtext rules: $@");
  }
}

# Real implementation is compiled in by finish_parsing_end; no-op otherwise.
sub _run_svgtext_rules { }

sub parsed_metadata {
  my ($self, $opts) = @_;
  $self->_run_svgtext_rules($opts);
}

sub _get_svg_text {
  my ($self, $pms) = @_;
  return ($pms->{Handler}{SVG} && $pms->{Handler}{SVG}{text}) || [];
}

# Eval rule: true if the ratio of SVG text words to graphics elements (summed
# across all SVG parts) is >= $min_ratio (default 1).  An SVG with text words but
# no graphics element has an infinite ratio and always fires.
sub check_svg_text_ratio {
  my ($self, $pms, $min_ratio) = @_;

  my $svg = $pms->{Handler}{SVG};
  return 0 unless $svg;

  my $words    = $svg->{word_count}     || 0;
  my $graphics = $svg->{graphics_count} || 0;
  return 0 unless $words;

  $min_ratio = 1 unless defined $min_ratio && $min_ratio ne '';

  # No graphics element at all -> infinite ratio -> always fires (given words).
  return 1 if $graphics == 0;
  return ($words / $graphics >= $min_ratio) ? 1 : 0;
}

1;
