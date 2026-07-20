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

Mail::SpamAssassin::Handler::ICS - A MIME-part handler for C<text/calendar> parts

=head1 SYNOPSIS

  loadhandler  Mail::SpamAssassin::Handler::ICS

  icstext  RULE_NAME  /pattern/modifiers

  body  ICS_MANY_ATTENDEES  eval:check_ics_attendee_count('50')
  body  ICS_RANDOM_DTSTART  eval:check_ics_random_start_time()

=head1 DESCRIPTION

This handler parses each iCalendar part and renders the B<text> of every event's
C<SUMMARY> and C<DESCRIPTION> into the message body, so ordinary C<body> rules can match
it.  The same text can additionally be matched with the new C<icstext> rule type, which
sees the invite text on its own -- so a word can be scored differently inside an invite
than in the surrounding body.  Links found in the C<URL>, C<ATTACH> and C<LOCATION>
properties are added to the URI detail list (type C<ics>).  It also counts C<ATTENDEE>
properties and flags events whose C<DTSTART> has a non-zero seconds component (a
fingerprint of machine-generated / bulk invites, since human and most-client invites
round to C<:00>) -- see L</EVAL RULES>.

=head1 RETURNS

This handler returns one C<text/html> sub-part for each HTML-typed property found,
or an empty list if there are none.

=head1 ICS TEXT RULES

  icstext  RULENAME  /regex/modifiers
  score    RULENAME  1.0
  describe RULENAME  ICS event text matching /regex/

These rules behave like C<rawbody> rules and support the C<multiple> and C<maxhits=N>
tflags.  By default a rule stops at its first match.  C<icstext> matches only the
invite text; to run one of the eval rules below, use a C<body> rule.

=head1 EVAL RULES

  check_ics_attendee_count(MIN, [MAX])

    body RULENAME  eval:check_ics_attendee_count(<min>,[max])
       min: required, invites contain at least x ATTENDEE properties in total
       max: optional, if specified, must not contain more than x ATTENDEE properties

  check_ics_random_start_time()

    body RULENAME  eval:check_ics_random_start_time()

       Fires if any event's DTSTART has a non-zero seconds component
       (e.g. DTSTART:20250610T120005Z) -- a fingerprint of a machine-generated
       start time, since human and most-client invites round to whole minutes.

  check_ics_event_prop(NAME, REGEX)

    body RULENAME  eval:check_ics_event_prop('ATTACH', 'ENCODING=BASE64')

       Fires if any calendar event has a property named NAME (case-insensitive)
       whose content matches REGEX.  The leading property NAME is stripped -- REGEX
       sees "params:value" (or just "value" when the property has no parameters) --
       so a rule for the DESCRIPTION value need not skip past a "DESCRIPTION:"
       prefix.  REGEX is a regular expression; the surrounding /.../ delimiters are
       optional, so 'ENCODING=BASE64' and '/ENCODING=BASE64/' are equivalent -- use
       the delimited form when you need flags (e.g. '/foo/i').  Note that even
       without delimiters it is still a regex, not a literal substring:
       metacharacters such as . | ( ) are active.  Because the parameters are
       retained, REGEX can still match them as well as the value -- e.g.
       ENCODING=BASE64, VALUE=BINARY, FMTTYPE=image/png.  Useful for finding
       invites that carry inline attachments or images.

=head1 URI DETAILS

This handler creates a new "ics" URI type. You can detect URIs found in calendar
invites using the L<URIDetail|Mail::SpamAssassin::Plugin::URIDetail> plugin. For example:

    uri-detail RULENAME  type =~ /^ics$/  raw =~ /^https?:\/\/bit\.ly\//

=cut

package Mail::SpamAssassin::Handler::ICS;

use strict;
use warnings;
use re 'taint';

use Mail::SpamAssassin::Handler;
use Mail::SpamAssassin::Logger qw(dbg would_log);
use Mail::SpamAssassin::Util qw(compile_regexp untaint_var);

# Regular expression to detect HTML
my $HTML_TAG_RE = qr{</?(?:a|abbr|b|blockquote|br|div|em|font|h[1-6]|i|img|li|ol
                       |p|span|strong|table|td|th|tr|u|ul)\b}xi;

our @ISA = qw(Mail::SpamAssassin::Handler);

sub log_dbg { Mail::SpamAssassin::Logger::dbg ("ics: @_"); }

sub new {
  my ($class, $mailsaobject) = @_;
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->register_eval_rule("check_ics_attendee_count",
                            $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule("check_ics_random_start_time",
                            $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule("check_ics_event_prop",
                            $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);

  $self->register_handler('text/calendar', 'handle_ics');

  $self->set_config($mailsaobject->{conf});

  return $self;
}

sub set_config {
  my ($self, $conf) = @_;
  my @cmds;

  push (@cmds, (
    {
      # icstext RULENAME /pattern/modifiers
      setting => 'icstext',
      is_priv => 1,
      type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
      code => sub {
        my ($self, $key, $value, $line) = @_;

        if ($value !~ /^(\S+)\s+(.+)$/) {
          return $Mail::SpamAssassin::Conf::INVALID_VALUE;
        }
        my ($name, $pattern) = ($1, $2);

        my ($re, $err) = compile_regexp($pattern, 1);
        if (!$re) {
          dbg("ics: invalid icstext regexp for $name '$pattern': $err");
          return $Mail::SpamAssassin::Conf::INVALID_VALUE;
        }

        $conf->{icstext_rules}->{$name} = $re;
        $self->{parser}->add_test($name, undef,
          $Mail::SpamAssassin::Conf::TYPE_EMPTY_TESTS);
      },
    },
  ));

  $conf->{parser}->register_commands(\@cmds);
}

# handle_ics($node, $pms): parse one iCalendar part.  Render its plain
# SUMMARY/DESCRIPTION text into the node (set_rendered) for body rules; add any URIs
# from URL/ATTACH/LOCATION to the URI detail list (type 'ics'); accumulate the
# ATTENDEE count and props across all parts.  Stashes the node in {ICS}{nodes} (so
# _get_ics_text can later gather its rendered text for icstext), and returns any
# HTML property as a text/html child part for the HTML handler.
sub handle_ics {
  my ($self, $node, $pms) = @_;

  my $data = $node->decode();
  return [] unless defined $data && length $data;

  my $ics = $pms->{Handler}{ICS} ||= {
    event_count => 0,
    props       => {},
    seen        => {},
    nodes       => [],   # every ICS part, for _get_ics_text to gather rendered text
  };

  # Parse the part into per-event records, then merge each event exactly once,
  # keyed by its UID.  Senders (e.g. Google Calendar) routinely attach the same
  # invite twice -- once inline as text/calendar and once as a base64
  # application/ics file -- and both copies reach the handler.  The two copies are
  # NOT byte-identical (different line folding / CRLF), so a raw-bytes fingerprint
  # would not catch them; the event UID is the RFC 5545 identity of the invite and
  # is stable across both serialisations.  Distinct events (e.g. recurrence
  # exceptions) have distinct UIDs and are all counted.
  my $events = $self->_parse_ics($data);

  my %content;   # MIME type => [ values ] from this node's (deduped) events

  for my $ev ( @$events ) {
    # Fall back to a content fingerprint for events with no UID, so duplicate
    # UID-less events across the two parts still collapse without merging
    # genuinely different UID-less events together.
    my $key = defined($ev->{uid}) && $ev->{uid} ne ''
      ? "uid:$ev->{uid}"
      : 'fp:'.join("\x00", (map { @{ $ev->{content}{$_} } } sort keys %{ $ev->{content} }),
                           map { $_->[0] } @{$ev->{uris}});

    if ($ics->{seen}{$key}++) {
      log_dbg("skipping duplicate event ($key): ".($node->{name} || '?'));
      next;
    }

    push @{ $content{$_} }, @{ $ev->{content}{$_} } for keys %{ $ev->{content} };

    for my $u ( @{ $ev->{uris} } ) {
      my ($uri, $tag) = @$u;
      # $tag records which property the URI came from (url/attach/location) for
      # the debug log only; the URI detail list is tagged just 'ics'.
      log_dbg("found URI ($tag): $uri");
      $pms->add_uri_detail_list($uri, { ics => 1 }, 'ICS');
    }

    $ics->{event_count}++;
    push @{ $ics->{props}{$_} }, @{ $ev->{props}{$_} } for keys %{ $ev->{props} };
    log_dbg("ICS event attendees=".scalar(@{ $ev->{props}{ATTENDEE} || [] })
            .": ".($node->{name} || '?'));
  }

  # Render this part's plain text into the node so ordinary body rules can match it.
  # Join the values with a blank line: get_body_text_array_common collapses single
  # newlines to spaces (only a blank line survives as a break), so a single "\n"
  # here would run consecutive properties together into one line.
  my $plain = delete $content{'text/plain'};
  if ($plain && @$plain) {
    $node->set_rendered(join("\n\n", @$plain)."\n", 'text/calendar');
  }

  # Stash every ICS part so _get_ics_text can gather rendered text from the node and
  # all its sub-parts, whatever their type (see _get_ics_text).
  push @{ $ics->{nodes} }, $node;

  # Hand every remaining content type to its handler as a child part.
  my @parts;
  for my $type ( sort keys %content ) {
    push @parts, { type => $type, data => $_ } for @{ $content{$type} };
  }
  return \@parts;
}

# _parse_ics($data): pure-Perl iCalendar parser.  Never dies (wrapped in eval);
# returns an arrayref of per-event records, one per VEVENT, each:
#   { uid => $uid, content => { MIME_type => [ value, ... ] },
#     uris => [ [uri, tag], ... ], props => { NAME => [ raw_line, ... ] } }.
# content holds the human-readable SUMMARY/DESCRIPTION/X-ALT-DESC values keyed by
# type ('text/plain' or 'text/html').
# props holds every property's raw (unfolded) content line keyed by upper-cased
# name, for check_ics_event_prop to search (the "random start time" signal is
# derived from the raw DTSTART line).  Returning per-event lets handle_ics dedupe
# by UID.  Only properties inside a VEVENT are considered.
sub _parse_ics {
  my ($self, $data) = @_;

  my @events;

  eval {
    # Normalise line endings, then unfold RFC 5545 folded lines: a CRLF (or LF)
    # followed by a single space or TAB is a continuation of the previous line.
    $data =~ s/\r\n?/\n/g;
    $data =~ s/\n[ \t]//g;

    my @stack;   # component nesting (BEGIN:/END:)
    my $ev;      # the VEVENT record currently being built, or undef
    for my $line (split /\n/, $data) {
      next if $line eq '';

      my ($name, $params, $val) = _split_content_line($line);
      next unless defined $name;
      $name = uc $name;   # property names are case-insensitive

      if ($name eq 'BEGIN') {
        my $comp = uc $val;
        push @stack, $comp;
        # Open a fresh event record when we enter a VEVENT.
        $ev = { uid => undef, content => {}, uris => [], props => {} }
          if $comp eq 'VEVENT';
        next;
      }
      if ($name eq 'END') {
        my $comp = pop @stack;
        if (defined $comp && $comp eq 'VEVENT' && $ev) {
          push @events, $ev;
          $ev = undef;
        }
        next;
      }

      # Only collect properties directly inside a VEVENT.
      next unless $ev && @stack && $stack[-1] eq 'VEVENT';

      # Retain every property's content (unfolded, minus the leading NAME) so
      # check_ics_event_prop can search arbitrary/extension properties, regardless
      # of the per-name cases below.  We keep any parameters ("params:value") -- so
      # ENCODING=BASE64 / VALUE=BINARY / FMTTYPE=... stay matchable -- but drop the
      # redundant property name, which the caller already supplied.
      push @{ $ev->{props}{$name} }, ($params ne '' ? "$params:$val" : $val);

      if ($name eq 'UID') {
        $ev->{uid} = $val if $val =~ /\S/;
      }
      elsif ($name eq 'SUMMARY') {
          my $t = _unescape_text($val);
          push @{ $ev->{content}{'text/plain'} }, $t if defined $t && $t =~ /\S/;
      }
      elsif ($name eq 'DESCRIPTION' || $name eq 'X-ALT-DESC') {
        my $is_html = $params =~ /(?:^|;)\s*FMTTYPE\s*=\s*text\/html\b/i
                      || $val =~ $HTML_TAG_RE;
        my $type = $is_html ? 'text/html' : 'text/plain';
        my $t = _unescape_text($val);
        push @{ $ev->{content}{$type} }, $t if defined $t && $t =~ /\S/;
      }
      elsif ($name eq 'URL') {
        push @{ $ev->{uris} }, [ $val, 'url' ] if $val =~ /\S/;
      }
      elsif ($name eq 'ATTACH') {
        # ATTACH is a URI unless it carries inline binary data.
        next if $params =~ /(?:^|;)\s*VALUE\s*=\s*BINARY\b/i;
        next if $params =~ /(?:^|;)\s*ENCODING\s*=\s*BASE64\b/i;
        push @{ $ev->{uris} }, [ $val, 'attach' ] if $val =~ /\S/;
      }
      elsif ($name eq 'LOCATION') {
        # LOCATION is usually free text; only treat it as a URI when it looks
        # like one.
        push @{ $ev->{uris} }, [ $val, 'location' ]
          if $val =~ m{^\s*(?:https?|ftp|mailto):}i;
      }
      # ATTENDEE and everything else are captured by the generic props push above;
      # check_ics_attendee_count counts the ATTENDEE lines directly.
    }
    1;
  } or do {
    my $err = $@;
    chomp $err;
    log_dbg("parse error: $err");
  };

  return \@events;
}

# _split_content_line($line): split an iCalendar content line into
# (NAME, PARAMS, VALUE).  NAME runs up to the first ';' or the first *unquoted* ':'.
# Params (between the first ';' and the unquoted ':') are returned verbatim.  The
# value is everything after the first unquoted ':'.  Quote-aware so a quoted param
# value containing a ':' (e.g. ALTREP="http://h:8080/") does not mis-split.
# Returns an empty list if there is no unquoted ':'.
sub _split_content_line {
  my ($line) = @_;

  my $in_quote = 0;
  my $colon = -1;
  my $semi  = -1;
  for (my $i = 0; $i < length($line); $i++) {
    my $c = substr($line, $i, 1);
    if ($c eq '"') {
      $in_quote = !$in_quote;
    }
    elsif (!$in_quote && $c eq ';' && $semi < 0) {
      $semi = $i;
    }
    elsif (!$in_quote && $c eq ':') {
      $colon = $i;
      last;
    }
  }
  return () if $colon < 0;

  my ($name, $params);
  if ($semi >= 0 && $semi < $colon) {
    $name   = substr($line, 0, $semi);
    $params = substr($line, $semi + 1, $colon - $semi - 1);
  } else {
    $name   = substr($line, 0, $colon);
    $params = '';
  }
  my $val = substr($line, $colon + 1);

  return ($name, $params, $val);
}

# _unescape_text($val): undo the RFC 5545 TEXT escapes for SUMMARY/DESCRIPTION.
# Intentionally loose -- the result only feeds user regexes.
sub _unescape_text {
  my ($val) = @_;
  return $val unless defined $val;
  $val =~ s/\\n/\n/gi;
  $val =~ s/\\([,;\\])/$1/g;
  return $val;
}

# Compile icstext rules into _run_icstext_rules, mirroring the SVG/PDF handlers.
sub finish_parsing_end {
  my ($self, $opts) = @_;
  my $conf = $opts->{conf};

  return unless exists $conf->{icstext_rules};

  my $would_log = would_log('dbg');

  my $eval = <<'EOF';
package Mail::SpamAssassin::Handler::ICS;

sub _run_icstext_rules {
    my ($self, $opts) = @_;
    my $pms = $opts->{permsgstatus};
    my ($test_qr, $hits);

    my $ics_text = $self->_get_ics_text($pms);
    return unless @$ics_text;

EOF

  my $loopid = 0;
  foreach my $name (keys %{$conf->{icstext_rules}}) {
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
    \$test_qr = \$pms->{conf}->{icstext_rules}->{$name};
    $init_hits
    rule_$loopid: foreach my \$line (\@\$ics_text) {
        $ifwhile ( \$line =~ /\$test_qr/$modifiers ) {
            my \$match = defined \${^MATCH} ? \${^MATCH} : '<negative match>';
            $dbg_ran_rule
            \$pms->got_hit('$name', 'ICS: ', 'ruletype' => 'rawbody');
            $last
        }
    }
EOF
  }

  $eval .= "}\n";

  no warnings 'redefine';
  eval untaint_var($eval);
  if ($@) {
    die("ics: error compiling icstext rules: $@");
  }
}

# Real implementation is compiled in by finish_parsing_end; no-op otherwise.
sub _run_icstext_rules { }

sub parsed_metadata {
  my ($self, $opts) = @_;
  my $pms = $opts->{permsgstatus};

  # Ensure the structure exists even when the message has no ICS parts, so the
  # eval rules can read the counters without autovivifying or dying.
  $pms->{Handler}{ICS} ||= {
    event_count => 0,
    props       => {},
    seen        => {},
    nodes       => [],
  };

  $self->_run_icstext_rules($opts);
}

# The text array that icstext rules match, built lazily and cached: the rendered
# text of every ICS part and all its sub-parts.  Called only from the compiled
# _run_icstext_rules, so this work happens only when there is at least one icstext
# rule.
sub _get_ics_text {
  my ($self, $pms) = @_;
  my $ics = $pms->{Handler}{ICS} or return [];
  return $ics->{text} if $ics->{text};   # cached

  my @text;
  for my $node ( @{ $ics->{nodes} || [] } ) {
    _gather_rendered($node, \@text);
  }
  return $ics->{text} = \@text;
}

# Append the visible rendered text of $node and, recursively, all of its
# handler-produced sub-parts to $out, one array element per non-blank line.
# icstext matches line by line, so a multi-line render is split back into lines.
sub _gather_rendered {
  my ($node, $out) = @_;
  my (undef, $text) = $node->rendered();   # ($type, $text)
  if (defined $text) {
    for my $line (split /\n/, $text) {
      push @$out, $line if $line =~ /\S/;
    }
  }
  _gather_rendered($_, $out) for @{ $node->{handler_parts} || [] };
}

# Eval rule: true if the total ATTENDEE count across all invites is in [min, max].
# Only fires when the message actually contains a calendar event -- otherwise a
# min of 0 (e.g. check_ics_attendee_count(0,0), "invites with no attendees") would
# match every message, since a message with no invite also has a zero count.
sub check_ics_attendee_count {
  my ($self, $pms, $body, $min, $max) = @_;
  return 0 unless $pms->{Handler}{ICS}->{event_count};
  my $count = scalar @{ $pms->{Handler}{ICS}->{props}{ATTENDEE} || [] };
  return _result_check($min, $max, $count);
}

# Eval rule: true if any event's DTSTART has a non-zero seconds component -- a
# fingerprint of a machine-generated (rather than human-picked) start time, since
# human and most-client invites round to whole minutes (YYYYMMDDTHHMM00).  Read the
# seconds straight off the raw DTSTART line (params like TZID sit before the value
# and can't contain a YYYYMMDDTHHMMSS block, so the anchor is safe).
sub check_ics_random_start_time {
  my ($self, $pms, $body) = @_;
  return 0 unless $pms->{Handler}{ICS}->{event_count};
  for my $l ( @{ $pms->{Handler}{ICS}->{props}{DTSTART} || [] } ) {
    return 1 if $l =~ /\d{8}T\d{4}(\d{2})/ && $1 ne '00';
  }
  return 0;
}

# Eval rule: true if any VEVENT contains a property named NAME whose content
# (unfolded, name-stripped) matches the regex.  Matches "params:value" (or just
# "value" when there are no params), so params like ENCODING=BASE64 / VALUE=BINARY
# / FMTTYPE=... stay visible, but the redundant NAME prefix is gone.
# Intended for hunting arbitrary/extension properties (ATTACH, IMAGE, X-*).
sub check_ics_event_prop {
  my ($self, $pms, $body, $name, $re) = @_;
  return 0 unless defined $name && defined $re;
  return 0 unless $pms->{Handler}{ICS}->{event_count};
  my $lines = $pms->{Handler}{ICS}->{props}->{uc $name} or return 0;
  # $re is a regex whose /.../ delimiters are optional; strip_delimiters == 2
  # strips the delimiters (and honours any trailing flags, e.g. "/foo/i") when
  # present, and otherwise accepts a bare pattern -- still a regex, not a literal.
  # (0 would NOT strip, compiling "/foo/" with the slashes as literal chars; 1
  # would strip but reject a bare pattern.)
  my ($qr, $err) = compile_regexp($re, 2);
  if (!$qr) {
    dbg("ics: invalid check_ics_event_prop regexp '$re': $err");
    return 0;
  }
  for my $l (@$lines) { return 1 if $l =~ $qr; }
  return 0;
}

sub _result_check {
  my ($min, $max, $value, $nomaxequal) = @_;
  return 0 unless defined $min && defined $value;
  return 0 if $value < $min;
  return 0 if defined $max && $value > $max;
  return 0 if defined $nomaxequal && $nomaxequal && $value == $max;
  return 1;
}

1;
