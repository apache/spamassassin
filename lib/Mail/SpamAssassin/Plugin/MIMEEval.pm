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

package Mail::SpamAssassin::Plugin::MIMEEval;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Locales;
use Mail::SpamAssassin::Constants qw(:sa CHARSETS_LIKELY_TO_FP_AS_CAPS);
use strict;
use warnings;
use bytes;

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  # the important bit!
  $self->register_eval_rule("check_for_mime");
  $self->register_eval_rule("check_for_mime_html");
  $self->register_eval_rule("check_for_mime_html_only");
  $self->register_eval_rule("check_mime_multipart_ratio");
  $self->register_eval_rule("check_msg_parse_flags");
  $self->register_eval_rule("check_for_faraway_charset");
  $self->register_eval_rule("check_for_uppercase");
  $self->register_eval_rule("check_ma_non_text");
  $self->register_eval_rule("check_base64_length");

  return $self;
}

###########################################################################

sub are_more_high_bits_set {
  my ($self, $str) = @_;

  # TODO: I suspect a tr// trick may be faster here
  my $numhis = () = ($str =~ /[\200-\377]/g);
  my $numlos = length($str) - $numhis;

  ($numlos <= $numhis && $numhis > 3);
}

sub check_for_faraway_charset {
  my ($self, $pms, $body) = @_;

  my $type = $pms->get('Content-Type');

  my @locales = Mail::SpamAssassin::Util::get_my_locales($self->{main}->{conf}->{ok_locales});

  return 0 if grep { $_ eq "all" } @locales;

  $type = get_charset_from_ct_line ($type);

  if (defined $type &&
    !Mail::SpamAssassin::Locales::is_charset_ok_for_locales
		    ($type, @locales))
  {
    # sanity check.  Some charsets (e.g. koi8-r) include the ASCII
    # 7-bit charset as well, so make sure we actually have a high
    # number of 8-bit chars in the body text first.

    $body = join("\n", @$body);
    if ($self->are_more_high_bits_set ($body)) {
      return 1;
    }
  }

  0;
}

sub check_for_mime {
  my ($self, $pms, undef, $test) = @_;

  $self->_check_attachments($pms) unless exists $pms->{$test};
  return $pms->{$test};
}

# any text/html MIME part
sub check_for_mime_html {
  my ($self, $pms) = @_;

  my $ctype = $pms->get('Content-Type');
  return 1 if (defined($ctype) && $ctype =~ m@^text/html@i);

  $self->_check_attachments($pms) unless exists $pms->{mime_body_html_count};
  return ($pms->{mime_body_html_count} > 0);
}

# HTML without some other type of MIME text part
sub check_for_mime_html_only {
  my ($self, $pms) = @_;

  my $ctype = $pms->get('Content-Type');
  return 1 if (defined($ctype) && $ctype =~ m@^text/html@i);

  $self->_check_attachments($pms) unless exists $pms->{mime_body_html_count};
  return ($pms->{mime_body_html_count} > 0 &&
	  $pms->{mime_body_text_count} == 0);
}

sub check_mime_multipart_ratio {
  my ($self, $pms, undef, $min, $max) = @_;

  $self->_check_attachments($pms) unless exists $pms->{mime_multipart_alternative};

  return ($pms->{mime_multipart_ratio} >= $min &&
	  $pms->{mime_multipart_ratio} < $max);
}

sub _check_mime_header {
  my ($self, $pms, $ctype, $cte, $cd, $charset, $name) = @_;

  $charset ||= '';

  if ($ctype eq 'text/html') {
    $pms->{mime_body_html_count}++;
  }
  elsif ($ctype =~ m@^text@i) {
    $pms->{mime_body_text_count}++;
  }

  if ($cte =~ /base64/) {
    $pms->{mime_base64_count}++;
  }
  elsif ($cte =~ /quoted-printable/) {
    $pms->{mime_qp_count}++;
  }

  if ($cd && $cd =~ /attachment/) {
    $pms->{mime_attachment}++;
  }

  if ($ctype =~ /^text/ &&
      $cte =~ /base64/ &&
      $charset !~ /(?:utf-8|big5)/ &&   # big5 due to bug 4687
      !($cd && $cd =~ /^(?:attachment|inline)/))
  {
    $pms->{mime_base64_encoded_text} = 1;
  }

  if ($charset =~ /iso-\S+-\S+\b/i &&
      $charset !~ /iso-(?:8859-\d{1,2}|2022-(?:jp|kr))\b/)
  {
    $pms->{mime_bad_iso_charset} = 1;
  }

  # MIME_BASE64_LATIN: now a zero-hitter
  # if (!$name &&
  # $cte =~ /base64/ &&
  # $charset =~ /\b(?:us-ascii|iso-8859-(?:[12349]|1[0345])|windows-(?:125[0247]))\b/)
  # {
  # $pms->{mime_base64_latin} = 1;
  # }

  # MIME_QP_NO_CHARSET: now a zero-hitter
  # if ($cte =~ /quoted-printable/ && $cd =~ /inline/ && !$charset) {
  # $pms->{mime_qp_inline_no_charset} = 1;
  # }

  # MIME_HTML_NO_CHARSET: now a zero-hitter
  # if ($ctype eq 'text/html' &&
  # !(defined($charset) && $charset) &&
  # !($cd && $cd =~ /^(?:attachment|inline)/))
  # {
  # $pms->{mime_html_no_charset} = 1;
  # }

  if ($charset =~ /[a-z]/i) {
    if (defined $pms->{mime_html_charsets}) {
      $pms->{mime_html_charsets} .= " ".$charset;
    } else {
      $pms->{mime_html_charsets} = $charset;
    }

    if (! $pms->{mime_faraway_charset}) {
      my @l = Mail::SpamAssassin::Util::get_my_locales($self->{main}->{conf}->{ok_locales});

      if (!(grep { $_ eq "all" } @l) &&
	  !Mail::SpamAssassin::Locales::is_charset_ok_for_locales($charset, @l))
      {
	$pms->{mime_faraway_charset} = 1;
      }
    }
  }
}

sub _check_attachments {
  my ($self, $pms) = @_;

  # MIME status
  my $where = -1;		# -1 = start, 0 = nowhere, 1 = header, 2 = body
  my $qp_bytes = 0;		# total bytes in QP regions
  my $qp_count = 0;		# QP-encoded bytes in QP regions
  my @part_bytes;		# MIME part total bytes
  my @part_type;		# MIME part types

  # MIME header information
  my $part = -1;		# MIME part index

  # indicate the scan has taken place
  $pms->{mime_checked_attachments} = 1;

  # results
  $pms->{mime_base64_blanks} = 0;
  $pms->{mime_base64_count} = 0;
  $pms->{mime_base64_encoded_text} = 0;
  # $pms->{mime_base64_illegal} = 0;
  # $pms->{mime_base64_latin} = 0;
  $pms->{mime_body_html_count} = 0;
  $pms->{mime_body_text_count} = 0;
  $pms->{mime_faraway_charset} = 0;
  # $pms->{mime_html_no_charset} = 0;
  $pms->{mime_missing_boundary} = 0;
  $pms->{mime_multipart_alternative} = 0;
  $pms->{mime_multipart_ratio} = 1.0;
  $pms->{mime_qp_count} = 0;
  # $pms->{mime_qp_illegal} = 0;
  # $pms->{mime_qp_inline_no_charset} = 0;
  $pms->{mime_qp_long_line} = 0;
  $pms->{mime_qp_ratio} = 0;

  # Get all parts ...
  foreach my $p ($pms->{msg}->find_parts(qr/./)) {
    # message headers
    my ($ctype, $boundary, $charset, $name) = Mail::SpamAssassin::Util::parse_content_type($p->get_header("content-type"));

    if ($ctype eq 'multipart/alternative') {
      $pms->{mime_multipart_alternative} = 1;
    }

    my $cte = $p->get_header('Content-Transfer-Encoding') || '';
    chomp($cte = defined($cte) ? lc $cte : "");

    my $cd = $p->get_header('Content-Disposition') || '';
    chomp($cd = defined($cd) ? lc $cd : "");

    $charset = lc $charset if ($charset);
    $name = lc $name if ($name);

    $self->_check_mime_header($pms, $ctype, $cte, $cd, $charset, $name);

    # If we're not in a leaf node in the tree, there will be no raw
    # section, so skip it.
    if (! $p->is_leaf()) {
      next;
    }

    $part++;
    $part_type[$part] = $ctype;
    $part_bytes[$part] = 0 if $cd !~ /attachment/;

    my $previous = '';
    foreach (@{$p->raw()}) {
      if ($cte =~ /base64/i) {
        if ($previous =~ /^\s*$/ && /^\s*$/) {
	  $pms->{mime_base64_blanks} = 1;
        }
        # MIME_BASE64_ILLEGAL: now a zero-hitter
        # if (m@[^A-Za-z0-9+/=\n]@ || /=[^=\s]/) {
        # $pms->{mime_base64_illegal} = 1;
        # }
      }

      # if ($pms->{mime_html_no_charset} && $ctype eq 'text/html' && defined $charset) {
      # $pms->{mime_html_no_charset} = 0;
      # }
      if ($pms->{mime_multipart_alternative} && $cd !~ /attachment/ &&
          ($ctype eq 'text/plain' || $ctype eq 'text/html')) {
	$part_bytes[$part] += length;
      }

      if ($where != 1 && $cte eq "quoted-printable" && ! /^SPAM: /) {
        if (length > 77) {
	  $pms->{mime_qp_long_line} = 1;
        }
        $qp_bytes += length;

        # MIME_QP_DEFICIENT: zero-hitter now

        # check for illegal substrings (RFC 2045), hexadecimal values 7F-FF and
        # control characters other than TAB, or CR and LF as parts of CRLF pairs
        # if (!$pms->{mime_qp_illegal} && /[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\xff]/)
        # {
        # $pms->{mime_qp_illegal} = 1;
        # }

        # count excessive QP bytes
        if (index($_, '=') != -1) {
	  # whoever wrote this next line is an evil hacker -- jm
	  my $qp = () = m/=(?:09|3[0-9ABCEF]|[2456][0-9A-F]|7[0-9A-E])/g;
	  if ($qp) {
	    $qp_count += $qp;
	    # tabs and spaces at end of encoded line are okay.  Also, multiple
	    # whitespace at the end of a line are OK, like ">=20=20=20=20=20=20".
	    my ($trailing) = m/((?:=09|=20)+)\s*$/g;
	    if ($trailing) {
	      $qp_count -= (length($trailing) / 3);
	    }
	  }
        }
      }
      $previous = $_;
    }
  }

  if ($qp_bytes) {
    $pms->{mime_qp_ratio} = $qp_count / $qp_bytes;
  }

  if ($pms->{mime_multipart_alternative}) {
    my $text;
    my $html;
    # bug 4207: we want the size of the last parts
    for (my $i = $part; $i >= 0; $i--) {
      next if !defined $part_bytes[$i];
      if (!defined($html) && $part_type[$i] eq 'text/html') {
	$html = $part_bytes[$i];
      }
      elsif (!defined($text) && $part_type[$i] eq 'text/plain') {
	$text = $part_bytes[$i];
      }
      last if (defined($html) && defined($text));
    }
    if (defined($text) && defined($html) && $html > 0) {
      $pms->{mime_multipart_ratio} = ($text / $html);
    }
  }

  # Look to see if any multipart boundaries are not "balanced"
  foreach my $val (values %{$pms->{msg}->{mime_boundary_state}}) {
    if ($val != 0) {
      $pms->{mime_missing_boundary} = 1;
      last;
    }
  }
}

sub check_msg_parse_flags {
  my($self, $pms, $type, $type2) = @_;
  $type = $type2 if ref($type);
  return defined $pms->{msg}->{$type};
}

sub check_for_uppercase {
  my ($self, $pms, $body, $min, $max) = @_;
  local ($_);

  if (exists $pms->{uppercase}) {
    return ($pms->{uppercase} > $min && $pms->{uppercase} <= $max);
  }

  if ($self->body_charset_is_likely_to_fp($pms)) {
    $pms->{uppercase} = 0; return 0;
  }

  # Dec 20 2002 jm: trade off some speed for low memory footprint, by
  # iterating over the array computing sums, instead of joining the
  # array into a giant string and working from that.

  my $len = 0;
  my $lower = 0;
  my $upper = 0;
  foreach (@{$body}) {
    # examine lines in the body that have an intermediate space
    next unless /\S\s+\S/;
    # strip out lingering base64 (currently possible for forwarded messages)
    next if /^(?:[A-Za-z0-9+\/=]{60,76} ){2}/;

    my $line = $_;	# copy so we don't muck up the original

    # remove shift-JIS charset codes
    $line =~ s/\x1b\$B.*\x1b\(B//gs;

    $len += length($line);

    # count numerals as lower case, otherwise 'date|mail' is spam
    $lower += ($line =~ tr/a-z0-9//d);
    $upper += ($line =~ tr/A-Z//);
  }

  # report only on mails above a minimum size; otherwise one
  # or two acronyms can throw it off
  if ($len < 200) {
    $pms->{uppercase} = 0;
    return 0;
  }
  if (($upper + $lower) == 0) {
    $pms->{uppercase} = 0;
  } else {
    $pms->{uppercase} = ($upper / ($upper + $lower)) * 100;
  }

  return ($pms->{uppercase} > $min && $pms->{uppercase} <= $max);
}

sub body_charset_is_likely_to_fp {
  my ($self, $pms) = @_;

  # check for charsets where this test will FP -- iso-2022-jp, gb2312,
  # koi8-r etc.
  #
  $self->_check_attachments($pms) unless exists $pms->{mime_checked_attachments};
  my @charsets = ();
  my $type = $pms->get('Content-Type');
  $type = get_charset_from_ct_line ($type);
  if (defined $type) {
    push (@charsets, $type);
  }
  if (defined $pms->{mime_html_charsets}) {
    push (@charsets, split(' ', $pms->{mime_html_charsets}));
  }

  my $CHARSETS_LIKELY_TO_FP_AS_CAPS = CHARSETS_LIKELY_TO_FP_AS_CAPS;
  foreach my $charset (@charsets) {
    if ($charset =~ /^${CHARSETS_LIKELY_TO_FP_AS_CAPS}$/) {
      return 1;
    }
  }
  return 0;
}

sub get_charset_from_ct_line {
  my $type = shift;
  if ($type =~ /charset="([^"]+)"/i) { return $1; }
  if ($type =~ /charset='([^']+)'/i) { return $1; }
  if ($type =~ /charset=(\S+)/i) { return $1; }
  return undef;
}

# came up on the users@ list, look for multipart/alternative parts which
# include non-text parts -- skip certain types which occur normally in ham
sub check_ma_non_text {
  my($self, $pms) = @_;

  foreach my $map ($pms->{msg}->find_parts(qr@^multipart/alternative$@i)) {
    foreach my $p ($map->find_parts(qr/./, 1, 0)) {
      next if (lc $p->{'type'} eq 'multipart/related');
      next if (lc $p->{'type'} eq 'application/rtf');
      next if ($p->{'type'} =~ m@^text/@i);
      return 1;
    }
  }
  
  return 0;
}

sub check_base64_length {
  my $self = shift;
  my $pms = shift;
  shift; # body array, unnecessary
  my $min = shift;
  my $max = shift;

  if (!defined $pms->{base64_length}) {
    $pms->{base64_length} = $self->_check_base64_length($pms->{msg});
  }

  return 0 if (defined $max && $pms->{base64_length} > $max);
  return $pms->{base64_length} >= $min;
}

sub _check_base64_length {
  my $self = shift;
  my $msg = shift;

  my $result = 0;

  foreach my $p ($msg->find_parts(qr@.@, 1)) {
    my $ctype=
      Mail::SpamAssassin::Util::parse_content_type($p->get_header('content-type'));

    # FPs from Google Calendar invites, etc.
    # perhaps just limit to test, and image?
    next if ($ctype eq 'application/ics');

    my $cte = lc $p->get_header('content-transfer-encoding') || '';
    next if ($cte !~ /^base64$/);
    foreach my $l ( @{$p->raw()} ) {
      my $len = length $l;
      $result = $len if ($len > $result);
    }
  }
  
  return $result;
}

1;
