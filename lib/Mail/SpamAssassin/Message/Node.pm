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

Mail::SpamAssassin::Message::Node - decode, render, and make available MIME message parts

=head1 SYNOPSIS

=head1 DESCRIPTION

This module will encapsulate an email message and allow access to
the various MIME message parts.

=head1 PUBLIC METHODS

=over 4

=cut

package Mail::SpamAssassin::Message::Node;

use strict;
use warnings;
use re 'taint';

require 5.008001;  # needs utf8::is_utf8()

use Mail::SpamAssassin;
use Mail::SpamAssassin::Constants qw(:sa);
use Mail::SpamAssassin::HTML;
use Mail::SpamAssassin::Logger;

our($enc_utf8, $enc_w1252, $have_encode_detector);
BEGIN {
  eval { require Encode }
    and do { $enc_utf8  = Encode::find_encoding('UTF-8');
             $enc_w1252 = Encode::find_encoding('Windows-1252') };
  eval { require Encode::Detect::Detector }
    and do { $have_encode_detector = 1 };
};

=item new()

Generates an empty Node object and returns it.  Typically only called
by functions in Message.

=cut

sub new {
  my $class = shift;
  $class = ref($class) || $class;

  my $self = {
    headers		=> {},
    raw_headers		=> {},
    header_order	=> []
  };

  # deal with any parameters
  my($opts) = @_;
  $self->{normalize} = $opts->{'normalize'} || 0;

  bless($self,$class);
  $self;
}

=item find_parts()

Used to search the tree for specific MIME parts.  An array of matching
Node objects (pointers into the tree) is returned.  The parameters that
can be passed in are (in order, all scalars):

Regexp - Used to match against each part's Content-Type header,
specifically the type and not the rest of the header.  ie: "Content-type:
text/html; encoding=quoted-printable" has a type of "text/html".  If no
regexp is specified, find_parts() will return an empty array.

Only_leaves - By default, find_parts() will return any part that matches
the regexp, including multipart.  If you only want to see leaves of the
tree (ie: parts that aren't multipart), set this to true (1).

Recursive - By default, when find_parts() finds a multipart which has
parts underneath it, it will recurse through all sub-children.  If set to 0,
only look at the part and any direct children of the part.

=cut

# Used to find any MIME parts whose simple content-type matches a given regexp
# Searches it's own and any children parts.  Returns an array of MIME
# objects which match.  Our callers may expect the default behavior which is a
# depth-first array of parts.
#
sub find_parts {
  my ($self, $re, $onlyleaves, $recursive) = @_;

  # Didn't pass an RE?  Just abort.
  return () unless defined $re && $re ne '';

  $onlyleaves = 0 unless defined $onlyleaves;

  my $depth;
  if (defined $recursive && $recursive == 0) {
    $depth = 1;
  }
  
  my @ret;
  my @search = ( $self );

  while (my $part = shift @search) {
    # If this object matches, mark it for return.
    my $amialeaf = $part->is_leaf();

    if ( $part->{'type'} =~ /$re/ && (!$onlyleaves || $amialeaf) ) {
      push(@ret, $part);
    }
  
    if ( !$amialeaf && (!defined $depth || $depth > 0)) {
      $depth-- if defined $depth;
      unshift(@search, @{$part->{'body_parts'}});
    }
  }

  return @ret;
}

=item header()

Stores and retrieves headers from a specific MIME part.  The first
parameter is the header name.  If there is no other parameter, the header
is retrieved.  If there is a second parameter, the header is stored.

Header names are case-insensitive and are stored in both raw and
decoded form.  Using header(), only the decoded form is retrievable.

For retrieval, if header() is called in an array context, an array will
be returned with each header entry in a different element.  In a scalar
context, the last specific header is returned.

ie: If 'Subject' is specified as the header, and there are 2 Subject
headers in a message, the last/bottom one in the message is returned in
scalar context or both are returned in array context.

=cut

# Store or retrieve headers from a given MIME object
#
sub header {
  my $self   = shift;
  my $rawkey = shift;

  return unless defined $rawkey;

  # we're going to do things case insensitively
  my $key    = lc($rawkey);

  # Trim whitespace off of the header keys
  $key       =~ s/^\s+//;
  $key       =~ s/\s+$//;

  if (@_) {
    my $raw_value = shift;
    return unless defined $raw_value;

    push @{ $self->{'header_order'} }, $rawkey;
    if ( !exists $self->{'headers'}->{$key} ) {
      $self->{'headers'}->{$key} = [];
      $self->{'raw_headers'}->{$key} = [];
    }

    my $dec_value = $raw_value;
    $dec_value =~ s/\n[ \t]+/ /gs;
    $dec_value =~ s/\s+$//s;
    $dec_value =~ s/^\s+//s;
    push @{ $self->{'headers'}->{$key} }, $self->_decode_header($dec_value,$key);

    push @{ $self->{'raw_headers'}->{$key} }, $raw_value;

    return $self->{'headers'}->{$key}->[-1];
  }

  if (wantarray) {
    return unless exists $self->{'headers'}->{$key};
    return @{ $self->{'headers'}->{$key} };
  }
  else {
    return '' unless exists $self->{'headers'}->{$key};
    return $self->{'headers'}->{$key}->[-1];
  }
}

=item raw_header()

Retrieves the raw version of headers from a specific MIME part.  The only
parameter is the header name.  Header names are case-insensitive.

For retrieval, if raw_header() is called in an array context, an array
will be returned with each header entry in a different element.  In a
scalar context, the last specific header is returned.

ie: If 'Subject' is specified as the header, and there are 2 Subject
headers in a message, the last/bottom one in the message is returned in
scalar context or both are returned in array context.

=cut

# Retrieve raw headers from a given MIME object
#
sub raw_header {
  my $self = shift;
  my $key  = lc(shift);

  # Trim whitespace off of the header keys
  $key       =~ s/^\s+//;
  $key       =~ s/\s+$//;

  if (wantarray) {
    return unless exists $self->{'raw_headers'}->{$key};
    return @{ $self->{'raw_headers'}->{$key} };
  }
  else {
    return '' unless exists $self->{'raw_headers'}->{$key};
    return $self->{'raw_headers'}->{$key}->[-1];
  }
}

=item add_body_part()

Adds a Node child object to the current node object.

=cut

# Add a MIME child part to ourselves
sub add_body_part {
  my($self, $part) = @_;

  dbg("message: added part, type: ".$part->{'type'});
  push @{ $self->{'body_parts'} }, $part;
}

=item is_leaf()

Returns true if the tree node in question is a leaf of the tree (ie:
has no children of its own).  Note: This function may return odd results
unless the message has been mime parsed via _do_parse()!

=cut

sub is_leaf {
  my($self) = @_;
  return !exists $self->{'body_parts'};
}

=item raw()

Return a reference to the the raw array.  Treat this as READ ONLY.

=cut

sub raw {
  my $self = shift;

  # Ok, if we're called we are expected to return an array.
  # so if it's a file reference, read in the message into an array...
  #
  # NOTE: that "ref undef" works, so don't bother checking for a defined var
  # first.
  if (ref $self->{'raw'} eq 'GLOB') {
    my $fd = $self->{'raw'};
    seek($fd, 0, 0)  or die "message: cannot rewind file: $!";

    # dbg("message: (raw) reading mime part from a temporary file");
    my($nread,$raw_str); $raw_str = '';
    while ( $nread=sysread($fd, $raw_str, 16384, length $raw_str) ) { }
    defined $nread  or die "error reading: $!";
    my @array = split(/^/m, $raw_str, -1);

    dbg("message: empty message read")  if $raw_str eq '';
    return \@array;
  }

  return $self->{'raw'};
}

=item decode()

If necessary, decode the part text as base64 or quoted-printable.
The decoded text will be returned as a scalar string.  An optional length
parameter can be passed in which limits how much decoded data is returned.
If the scalar isn't needed, call with "0" as a parameter.

=cut

sub decode {
  my($self, $bytes) = @_;

  if ( !exists $self->{'decoded'} ) {
    # Someone is looking for a decoded part where there is no raw data
    # (multipart or subparsed message, etc.)  Just return undef.
    return  if !exists $self->{'raw'};

    my $raw;

    # if the part is held in a temp file, read it into the scalar
    if (ref $self->{'raw'} eq 'GLOB') {
      my $fd = $self->{'raw'};
      seek($fd, 0, 0)  or die "message: cannot rewind file: $!";

      # dbg("message: (decode) reading mime part from a temporary file");
      my($nread,$raw_str); $raw = '';
      while ( $nread=sysread($fd, $raw, 16384, length $raw) ) { }
      defined $nread  or die "error reading: $!";

      dbg("message: empty message read from a temp file")  if $raw eq '';
    }
    else {
      # create a new scalar from the raw array in memory
      $raw = join('', @{$self->{'raw'}});
    }

    my $encoding = lc $self->header('content-transfer-encoding') || '';

    if ( $encoding eq 'quoted-printable' ) {
      dbg("message: decoding quoted-printable");
      $self->{'decoded'} = Mail::SpamAssassin::Util::qp_decode($raw);
      $self->{'decoded'} =~ s/\015\012/\012/gs;
    }
    elsif ( $encoding eq 'base64' ) {
      dbg("message: decoding base64");

      # if it's not defined or is 0, do the whole thing, otherwise only decode
      # a portion
      if ($bytes) {
        return Mail::SpamAssassin::Util::base64_decode($raw, $bytes);
      }
      else {
        # Generate the decoded output
        $self->{'decoded'} = Mail::SpamAssassin::Util::base64_decode($raw);
      }

      if ( $self->{'type'} =~ m@^(?:text|message)\b/@i ) {
        $self->{'decoded'} =~ s/\015\012/\012/gs;
      }
    }
    else {
      # Encoding is one of 7bit, 8bit, binary or x-something
      if ( $encoding ) {
        dbg("message: decoding other encoding type ($encoding), ignoring");
      }
      else {
        dbg("message: no encoding detected");
      }
      $self->{'decoded'} = $raw;
    }
  }

  if ( !defined $bytes || $bytes ) {
    if ( !defined $bytes ) {
      # force a copy
      return '' . $self->{'decoded'};
    }
    else {
      return substr($self->{'decoded'}, 0, $bytes);
    }
  }
}

# Look at a text scalar and determine whether it should be rendered
# as text/html.
#
# This is not a public function.
# 
sub _html_render {
  if ($_[0] =~ m/^(.{0,18}?<(?:body|head|html|img|pre|table|title)(?:\s.{0,18}?)?>)/is)
  {
    my $pad = $1;
    my $count = 0;
    $count += ($pad =~ tr/\n//d) * 2;
    $count += ($pad =~ tr/\n//cd);
    return ($count < 24);
  }
  return 0;
}

# Decode character set of a given text to perl characters (Unicode),
# then encode into UTF-8 octets if requested.
#
sub _normalize {
  my $self = $_[0];
# my $data = $_[1];  # avoid copying large strings
  my $charset_declared = $_[2];
  my $return_decoded = $_[3];  # true: Unicode characters, false: UTF-8 octets

  return $_[1]  unless $self->{normalize} && $enc_utf8;

  warn "message: _normalize() was given characters, expected bytes: $_[1]\n"
    if utf8::is_utf8($_[1]);

  # workaround for Encode::decode taint laundering bug [rt.cpan.org #84879]
  my $data_taint = substr($_[1], 0, 0);  # empty string, tainted like $data

  if (!defined $charset_declared || $charset_declared eq '') {
    $charset_declared = 'us-ascii';
  }

  # number of characters with code above 127
  my $cnt_8bits = $_[1] =~ tr/\x00-\x7F//c;

  if (!$cnt_8bits &&
      $charset_declared =~
        /^(?: (?:US-)?ASCII | ANSI[_ ]? X3\.4- (?:1986|1968) |
              ISO646-US )\z/xsi)
  { # declared as US-ASCII (a.k.a. ANSI X3.4-1986) and it really is
    dbg("message: kept, charset is US-ASCII as declared");
    return $_[1];  # is all-ASCII, no need for decoding
  }

  if (!$cnt_8bits &&
      $charset_declared =~
        /^(?: ISO[ -]?8859 (?: - \d{1,2} )? | Windows-\d{4} |
              UTF-?8 | (KOI8|EUC)-[A-Z]{1,2} |
              Big5 | GBK | GB[ -]?18030 (?:-20\d\d)? )\z/xsi)
  { # declared as extended ASCII, but it is actually a plain 7-bit US-ASCII
    dbg("message: kept, charset is US-ASCII, declared %s", $charset_declared);
    return $_[1];  # is all-ASCII, no need for decoding
  }

  # Try first to strictly decode based on a declared character set.

  my $rv;
  if ($charset_declared =~ /^UTF-?8\z/i) {
    # attempt decoding as strict UTF-8  (flags: FB_CROAK | LEAVE_SRC)
    if (eval { $rv = $enc_utf8->decode($_[1], 1|8); defined $rv }) {
      dbg("message: decoded as declared charset UTF-8");
      return $_[1]  if !$return_decoded;
      $rv .= $data_taint;  # carry taintedness over, avoid Encode bug
      return $rv;  # decoded
    } else {
      dbg("message: failed decoding as declared charset UTF-8");
    };

  } elsif ($cnt_8bits &&
           eval { $rv = $enc_utf8->decode($_[1], 1|8); defined $rv }) {
    dbg("message: decoded as charset UTF-8, declared %s", $charset_declared);
    return $_[1]  if !$return_decoded;
    $rv .= $data_taint;  # carry taintedness over, avoid Encode bug
    return $rv;  # decoded

  } elsif ($charset_declared =~ /^(?:US-)?ASCII\z/i) {
    # declared as US-ASCII but contains 8-bit characters, makes no sense
    # to attempt decoding first as strict US-ASCII as we know it would fail

  } else {
    # try decoding as a declared character set

    # ->  http://en.wikipedia.org/wiki/Windows-1252
    # Windows-1252 character encoding is a superset of ISO 8859-1, but differs
    # from the IANA's ISO-8859-1 by using displayable characters rather than
    # control characters in the 80 to 9F (hex) range. [...]
    # It is very common to mislabel Windows-1252 text with the charset label
    # ISO-8859-1. A common result was that all the quotes and apostrophes
    # (produced by "smart quotes" in word-processing software) were replaced
    # with question marks or boxes on non-Windows operating systems, making
    # text difficult to read. Most modern web browsers and e-mail clients
    # treat the MIME charset ISO-8859-1 as Windows-1252 to accommodate
    # such mislabeling. This is now standard behavior in the draft HTML 5
    # specification, which requires that documents advertised as ISO-8859-1
    # actually be parsed with the Windows-1252 encoding.
    #
    my($chset, $decoder);
    if ($charset_declared =~ /^(?: ISO-?8859-1 | Windows-1252 | CP1252 )\z/xi) {
      $chset = 'Windows-1252'; $decoder = $enc_w1252;
    } else {
      $chset = $charset_declared; $decoder = Encode::find_encoding($chset);
      if (!$decoder && $chset =~ /^GB[ -]?18030(?:-20\d\d)?\z/i) {
        $decoder = Encode::find_encoding('GBK');  # a subset of GB18030
        dbg("message: no decoder for a declared charset %s, using GBK",
            $chset)  if $decoder;
      }
    }
    if (!$decoder) {
      dbg("message: failed decoding, no decoder for a declared charset %s",
          $chset);
    } else {
      eval { $rv = $decoder->decode($_[1], 1|8) };  # FB_CROAK | LEAVE_SRC
      if (lc $chset eq lc $charset_declared) {
        dbg("message: %s as declared charset %s",
            defined $rv ? 'decoded' : 'failed decoding', $charset_declared);
      } else {
        dbg("message: %s as charset %s, declared %s",
            defined $rv ? 'decoded' : 'failed decoding',
            $chset, $charset_declared);
      }
    }
  }

  # If the above failed, check if it is US-ASCII, possibly extended by few
  # NBSP or SHY characters from ISO-8859-* or Windows-1252, or containing
  # some popular punctuation or special characters from Windows-1252 in
  # the \x80-\x9F range (which is unassigned in ISO-8859-*).
  # Note that Windows-1252 is a proper superset of ISO-8859-1.
  #
  if (!defined $rv && !$cnt_8bits) {
    dbg("message: kept, guessed charset is US-ASCII, declared %s",
        $charset_declared);
    return $_[1];  # is all-ASCII, no need for decoding

  } elsif (!defined $rv && $enc_w1252 &&
      #             ASCII  NBSP (c) SHY  '   "  ...   '".-   TM
      $_[1] !~ tr/\x00-\x7F\xA0\xA9\xAD\x82\x84\x85\x91-\x97\x99//c)
  { # ASCII + NBSP + SHY + some punctuation characters
    # NBSP (A0) and SHY (AD) are at the same position in ISO-8859-* too
    # consider also: AE (r), 80 Euro
    eval { $rv = $enc_w1252->decode($_[1], 1|8) };  # FB_CROAK | LEAVE_SRC
    # the above can't fail, but keep code general just in case
    dbg("message: %s as guessed charset %s, declared %s",
        defined $rv ? 'decoded' : 'failed decoding',
        'Windows-1252', $charset_declared);
  }

  # If we were unsuccessful so far, try some guesswork
  # based on Encode::Detect::Detector .

  if (defined $rv) {
    # done, no need for guesswork
  } elsif (!$have_encode_detector) {
    dbg("message: Encode::Detect::Detector not available, declared %s failed",
        $charset_declared);
  } else {
    my $charset_detected = Encode::Detect::Detector::detect($_[1]);
    if ($charset_detected && lc $charset_detected ne lc $charset_declared) {
      my $decoder = Encode::find_encoding($charset_detected);
      if (!$decoder && $charset_detected =~ /^GB[ -]?18030(?:-20\d\d)?\z/i) {
        $decoder = Encode::find_encoding('GBK');  # a subset of GB18030
        dbg("message: no decoder for a detected charset %s, using GBK",
            $charset_detected)  if $decoder;
      }
      if (!$decoder) {
        dbg("message: failed decoding, no decoder for a detected charset %s",
            $charset_detected);
      } else {
        eval { $rv = $decoder->decode($_[1], 1|8) };  # FB_CROAK | LEAVE_SRC
        dbg("message: %s as detected charset %s, declared %s",
            defined $rv ? 'decoded' : 'failed decoding',
            $charset_detected, $charset_declared);
      }
    }
  }

  if (!defined $rv) {  # all decoding attempts failed so far, probably garbage
    # go for Windows-1252 which can't fail
    eval { $rv = $enc_w1252->decode($_[1]) };
    dbg("message: %s as last-resort charset %s, declared %s",
        defined $rv ? 'decoded' : 'failed decoding',
        'Windows-1252', $charset_declared);
  }

  if (!defined $rv) {  # just in case - all decoding attempts failed so far
    return $_[1];  # garbage-in / garbage-out, return unchanged octets
  }
  # decoding octets to characters was successful
  if (!$return_decoded) {
    # utf8::encode() is much faster than $enc_utf8->encode on utf8-flagged arg
    utf8::encode($rv);  # encode Unicode characters to UTF-8 octets
  }
  $rv .= $data_taint;  # carry taintedness over, avoid Encode bug
  return $rv;
}

=item rendered()

render_text() takes the given text/* type MIME part, and attempts to
render it into a text scalar.  It will always render text/html, and will
use a heuristic to determine if other text/* parts should be considered
text/html.  Two scalars are returned: the rendered type (either text/html
or whatever the original type was), and the rendered text.

=cut

sub rendered {
  my ($self) = @_;

  if (!exists $self->{rendered}) {
    # We only know how to render text/plain and text/html ...
    # Note: for bug 4843, make sure to skip text/calendar parts
    # we also want to skip things like text/x-vcard
    # text/x-aol is ignored here, but looks like text/html ...
    return(undef,undef) unless ( $self->{'type'} =~ /^text\/(?:plain|html)$/i );

    my $text = $self->decode;  # QP and Base64 decoding, bytes
    my $text_len = length($text);  # num of bytes in original charset encoding

    # render text/html always, or any other text|text/plain part as text/html
    # based on a heuristic which simulates a certain common mail client
    if ($text ne '' && ($self->{'type'} =~ m{^text/html$}i ||
		        ($self->{'type'} =~ m{^text/plain$}i &&
		         _html_render(substr($text, 0, 23)))))
    {
      $self->{rendered_type} = 'text/html';

      # will input text to HTML::Parser be provided as Unicode characters?
      my $character_semantics = 0;  # $text is in bytes
      if ($self->{normalize} && $enc_utf8) {  # charset decoding requested
        # Provide input to HTML::Parser as Unicode characters
        # which avoids a HTML::Parser bug in utf8_mode
        #   https://rt.cpan.org/Public/Bug/Display.html?id=99755
        # Avoid unnecessary step of encoding-then-decoding by telling
        # subroutine _normalize() to return Unicode text.  See Bug 7133
        #
        $character_semantics = 1;  # $text will be in characters
        $text = $self->_normalize($text, $self->{charset}, 1); # bytes to chars
      } elsif (!defined $self->{charset} ||
               $self->{charset} =~ /^(?:US-ASCII|UTF-8)\z/i) {
        # With some luck input can be interpreted as UTF-8, do not warn.
        # It is still possible to hit the HTML::Parses utf8_mode bug however.
      } else {
        dbg("message: 'normalize_charset' is off, encoding will likely ".
            "be misinterpreted; declared charset: %s", $self->{charset});
      }
      # the 0 requires decoded HTML results to be in bytes (not characters)
      my $html = Mail::SpamAssassin::HTML->new($character_semantics,0); # object

      $html->parse($text);  # parse+render text

      # resulting HTML-decoded text is in bytes, likely encoded as UTF-8
      $self->{rendered} = $html->get_rendered_text();
      $self->{visible_rendered} = $html->get_rendered_text(invisible => 0);
      $self->{invisible_rendered} = $html->get_rendered_text(invisible => 1);
      $self->{html_results} = $html->get_results();

      # end-of-document result values that require looking at the text
      my $r = $self->{html_results};	# temporary reference for brevity

      # count the number of spaces in the rendered text (likely UTF-8 octets)
      my $space = $self->{rendered} =~ tr/ \t\n\r\x0b//;
      # we may want to add the count of other Unicode whitespace characters

      $r->{html_length} = length $self->{rendered};  # bytes (likely UTF-8)
      $r->{non_space_len} = $r->{html_length} - $space;
      $r->{ratio} = ($text_len - $r->{html_length}) / $text_len  if $text_len;
    }

    else {  # plain text
      if ($self->{normalize} && $enc_utf8) {
        # request transcoded result as UTF-8 octets!
        $text = $self->_normalize($text, $self->{charset}, 0);
      }
      $self->{rendered_type} = $self->{type};
      $self->{rendered} = $self->{'visible_rendered'} = $text;
      $self->{'invisible_rendered'} = '';
    }
  }

  return ($self->{rendered_type}, $self->{rendered});
}

=item set_rendered($text, $type)

Set the rendered text and type for the given part.  If type is not
specified, and text is a defined value, a default of 'text/plain' is used.
This can be used, for instance, to render non-text parts using plugins.

=cut

sub set_rendered {
  my ($self, $text, $type) = @_;

  $type = 'text/plain' if (!defined $type && defined $text);

  $self->{'rendered_type'} = $type;
  $self->{'rendered'} = $self->{'visible_rendered'} = $text;
  $self->{'invisible_rendered'} = defined $text ? '' : undef;
}

=item visible_rendered()

Render and return the visible text in this part.

=cut

sub visible_rendered {
  my ($self) = @_;
  $self->rendered();  # ignore return, we want just this:
  return ($self->{rendered_type}, $self->{visible_rendered});
}

=item invisible_rendered()

Render and return the invisible text in this part.

=cut

sub invisible_rendered {
  my ($self) = @_;
  $self->rendered();  # ignore return, we want just this:
  return ($self->{rendered_type}, $self->{invisible_rendered});
}

=item content_summary()

Returns an array of scalars describing the mime parts of the message.
Note: This function requires that the message be parsed first!

=cut

# return an array with scalars describing mime parts
sub content_summary {
  my($self) = @_;

  my @ret = ( [ $self->{'type'} ] );
  my @search;

  if (exists $self->{'body_parts'}) {
    my $count = @{$self->{'body_parts'}};
    for(my $i=0; $i<$count; $i++) {
      push(@search, [ $i+1, $self->{'body_parts'}->[$i] ]);
    }
  }

  while(my $part = shift @search) {
    my($index, $part) = @{$part};
    push(@{$ret[$index]}, $part->{'type'});
    if (exists $part->{'body_parts'}) {
      unshift(@search, map { [ $index, $_ ] } @{$part->{'body_parts'}});
    }
  }

  return map { join(",", @{$_}) } @ret;
}

=item delete_header()

Delete the specified header (decoded and raw) from the Node information.

=cut

sub delete_header {
  my($self, $hdr) = @_;

  foreach ( grep(/^${hdr}$/i, keys %{$self->{'headers'}}) ) {
    delete $self->{'headers'}->{$_};
    delete $self->{'raw_headers'}->{$_};
  }
  
  my @neworder = grep(!/^${hdr}$/i, @{$self->{'header_order'}});
  $self->{'header_order'} = \@neworder;
}

# decode a header appropriately.  don't bother adding it to the pod documents.
sub __decode_header {
  my ( $self, $encoding, $cte, $data ) = @_;

  if ( $cte eq 'B' ) {
    # base 64 encoded
    $data = Mail::SpamAssassin::Util::base64_decode($data);
  }
  elsif ( $cte eq 'Q' ) {
    # quoted printable

    # the RFC states that in the encoded text, "_" is equal to "=20"
    $data =~ s/_/=20/g;

    $data = Mail::SpamAssassin::Util::qp_decode($data);
  }
  else {
    # not possible since the input has already been limited to 'B' and 'Q'
    die "message: unknown encoding type '$cte' in RFC2047 header";
  }
  return $self->_normalize($data, $encoding, 0);  # transcode to UTF-8 octets
}

# Decode base64 and quoted-printable in headers according to RFC2047.
#
sub _decode_header {
  my($self, $header_field_body, $header_field_name) = @_;

  return '' unless defined $header_field_body && $header_field_body ne '';

  # deal with folding and cream the newlines and such
  $header_field_body =~ s/\n[ \t]+/\n /g;
  $header_field_body =~ s/\015?\012//gs;

  if ($header_field_name =~
       /^ (?: (?: Received | (?:Resent-)? (?: Message-ID | Date ) |
                  MIME-Version | References | In-Reply-To ) \z
            | (?: List- | Content- ) ) /xsi ) {
    # Bug 6945: some header fields must not be processed for MIME encoding

  } else {
    local($1,$2,$3);

    # Multiple encoded sections must ignore the interim whitespace.
    # To avoid possible FPs with (\s+(?==\?))?, look for the whole RE
    # separated by whitespace.
    1 while $header_field_body =~
              s{ ( = \? [A-Za-z0-9_-]+ \? [bqBQ] \? [^?]* \? = ) \s+
                 ( = \? [A-Za-z0-9_-]+ \? [bqBQ] \? [^?]* \? = ) }
               {$1$2}xsg;

    # transcode properly encoded RFC 2047 substrings into UTF-8 octets,
    # leave everything else unchanged as it is supposed to be UTF-8 (RFC 6532)
    # or plain US-ASCII
    $header_field_body =~
      s{ (?: = \? ([A-Za-z0-9_-]+) \? ([bqBQ]) \? ([^?]*) \? = ) }
       { $self->__decode_header($1, uc($2), $3) }xsge;
  }

# dbg("message: _decode_header %s: %s", $header_field_name, $header_field_body);
  return $header_field_body;
}

=item get_header()

Retrieve a specific header.  Will have a newline at the end and will be
unfolded.  The first parameter is the header name (case-insensitive),
and the second parameter (optional) is whether or not to return the
raw header.

If get_header() is called in an array context, an array will be returned
with each header entry in a different element.  In a scalar context,
the last specific header is returned.

ie: If 'Subject' is specified as the header, and there are 2 Subject
headers in a message, the last/bottom one in the message is returned in
scalar context or both are returned in array context.

Btw, returning the last header field (not the first) happens to be consistent
with DKIM signatures, which search for and cover multiple header fields
bottom-up according to the 'h' tag. Let's keep it this way.

=cut

sub get_header {
  my ($self, $hdr, $raw) = @_;
  $raw ||= 0;

  # And now pick up all the entries into a list
  # This is assumed to include a newline at the end ...
  # This is also assumed to have removed continuation bits ...

  # Deal with the possibility that header() or raw_header() returns undef
  my @hdrs;
  if ( $raw ) {
    if (@hdrs = $self->raw_header($hdr)) {
      s/\015?\012\s+/ /gs  for @hdrs;
    }
  }
  else {
    if (@hdrs = $self->header($hdr)) {
      $_ .= "\n"  for @hdrs;
    }
  }

  if (wantarray) {
    return @hdrs;
  }
  else {
    return @hdrs ? $hdrs[-1] : undef;
  }
}

=item get_all_headers()

Retrieve all headers.  Each header will have a newline at the end and
will be unfolded.  The first parameter (optional) is whether or not to
return the raw headers, and the second parameter (optional) is whether
or not to include the mbox separator.

If get_all_header() is called in an array context, an array will be
returned with each header entry in a different element.  In a scalar
context, the headers are returned in a single scalar.

=back

=cut

# build it and it will not bomb
sub get_all_headers {
  my ($self, $raw, $include_mbox) = @_;
  $raw ||= 0;
  $include_mbox ||= 0;

  my @lines;

  # precalculate destination positions based on order of appearance
  my $i = 0;
  my %locations;
  for my $k (@{$self->{header_order}}) {
    push(@{$locations{lc($k)}}, $i++);
  }

  # process headers in order of first appearance
  my $header;
  my $size = 0;
  HEADER: for my $name (sort { $locations{$a}->[0] <=> $locations{$b}->[0] }
			keys %locations)
  {
    # get all same-name headers and poke into correct position
    my $positions = $locations{$name};
    for my $contents ($self->get_header($name, $raw)) {
      my $position = shift @{$positions};
      $size += length($name) + length($contents) + 2;
      if ($size > MAX_HEADER_LENGTH) {
	$self->{'truncated_header'} = 1;
	last HEADER;
      }
      $lines[$position] = $self->{header_order}->[$position].":".$contents;
    }
  }

  # skip undefined lines if we truncated
  @lines = grep { defined $_ } @lines if $self->{'truncated_header'};

  splice @lines, 0, 0, $self->{mbox_sep} if ( $include_mbox && exists $self->{mbox_sep} );

  return wantarray ? @lines : join ('', @lines);
}

# legacy public API; now a no-op.
sub finish { }

# ---------------------------------------------------------------------------

1;
__END__
