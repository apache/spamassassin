# $Id: MIME.pm,v 1.8 2003/10/02 22:59:00 quinlan Exp $

# <@LICENSE>
# Copyright 2004 Apache Software Foundation
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
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

Mail::SpamAssassin::MsgContainer - decode, render, and make available MIME message parts

=head1 SYNOPSIS

=head1 DESCRIPTION

This module will encapsulate an email message and allow access to
the various MIME message parts.

=head1 PUBLIC METHODS

=over 4

=cut

package Mail::SpamAssassin::MsgContainer;
use strict;
use MIME::Base64;
use Mail::SpamAssassin;
use Mail::SpamAssassin::HTML;
use Mail::SpamAssassin::MsgMetadata;
use MIME::Base64;
use MIME::QuotedPrint;

=item new()

=cut

# M::SA::MIME is an object method used to encapsulate a message's MIME part
#
sub new {
  my $class = shift;
  $class = ref($class) || $class;
  my %opts = @_;

  my $self = {
    headers		=> {},
    raw_headers		=> {},
    body_parts		=> [],
    header_order	=> [],
    already_parsed	=> 1,
    };

  # allow callers to set certain options ...
  foreach ( 'already_parsed' ) {
    $self->{$_} = $opts{$_} if ( exists $opts{$_} );
  }

  bless($self,$class);

  $self;
}

=item _set_is_root()

Non-Public function to inform this node that it's the root, and
can hold stuff that only a root should do.

(TODO: IMO, we should just have a subclass of MsgContainer for
root nodes.)

=cut

sub _set_is_root {
  my($self) = @_;

  # create the metadata holder class
  $self->{metadata} = Mail::SpamAssassin::MsgMetadata->new($self);
}

=item _do_parse()

Non-Public function which will initiate a MIME part part (generates
a tree) of the current message.  Typically called by find_parts()
as necessary.

=cut

sub _do_parse {
  my($self) = @_;

  # If we're called when we don't need to be, then just go ahead and return.
  return if ($self->{'already_parsed'});

  my $toparse = $self->{'toparse'};
  delete $self->{'toparse'};

  dbg("---- MIME PARSER START ----");

  # Figure out the boundary
  my ($boundary);
  ($self->{'type'}, $boundary) = Mail::SpamAssassin::Util::parse_content_type($self->header('content-type'));
  dbg("main message type: ".$self->{'type'});

  # Make the tree
  Mail::SpamAssassin::MsgParser->parse_body( $self, $self, $boundary, $toparse, 1 );
  $self->{'already_parsed'} = 1;

  dbg("---- MIME PARSER END ----");

  return;
}

=item find_parts()

=cut

# Used to find any MIME parts whose simple content-type matches a given regexp
# Searches it's own and any children parts.  Returns an array of MIME
# objects which match.
#
sub find_parts {
  my ($self, $re, $onlyleaves, $recursive) = @_;

  # Didn't pass an RE?  Just abort.
  return () unless $re;

  $onlyleaves = 0 unless defined $onlyleaves;
  $recursive = 1 unless defined $recursive;

  # ok, we need to do the parsing now...
  $self->_do_parse() if (!$self->{'already_parsed'});
  
  return $self->_find_parts($re, $onlyleaves, $recursive);
}

# We have 2 functions in find_parts() to optimize out the penalty of
# 'already_parsed'...  It also lets us avoid checking $onlyleaves, $re,
# and $recursive over and over again.
#
sub _find_parts {
  my ($self, $re, $onlyleaves, $recursive) = @_;
  my @ret = ();

  # If this object matches, mark it for return.
  my $amialeaf = $self->is_leaf();

  if ( $self->{'type'} =~ /$re/ && (!$onlyleaves || $amialeaf) ) {
    push(@ret, $self);
  }
  
  if ( $recursive && !$amialeaf ) {
    # This object is a subtree root.  Search all children.
    foreach my $parts ( @{$self->{'body_parts'}} ) {
      # Add the recursive results to our results
      push(@ret, $parts->_find_parts($re));
    }
  }

  return @ret;
}

=item header()

=cut

# Store or retrieve headers from a given MIME object
#
sub header {
  my $self   = shift;
  my $rawkey = shift;
  my $key    = lc($rawkey);

  # Trim whitespace off of the header keys
  $key       =~ s/^\s+//;
  $key       =~ s/\s+$//;

  if (@_) {
    my $raw_value = shift;
    push @{ $self->{'header_order'} }, $rawkey;
    if ( !exists $self->{'headers'}->{$key} ) {
      $self->{'headers'}->{$key} = [];
      $self->{'raw_headers'}->{$key} = [];
    }

    push @{ $self->{'headers'}->{$key} },     _decode_header($raw_value);
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

=cut

# Add a MIME child part to ourselves
sub add_body_part {
  my($self, $part) = @_;

  dbg("added part, type: ".$part->{'type'});
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

Return a reference to the the raw array.

=cut

sub raw {
  return $_[0]->{'raw'};
}

=item decode()

Decode base64 and quoted-printable parts.

=cut

# TODO: accept a length param
sub decode {
  my($self, $bytes) = @_;

  if ( !exists $self->{'decoded'} ) {
    my $encoding = lc $self->header('content-transfer-encoding') || '';

    if ( $encoding eq 'quoted-printable' ) {
      dbg("decoding: quoted-printable");
      $self->{'decoded'} = [
        map { s/\r\n/\n/; $_; } split ( /^/m, Mail::SpamAssassin::Util::qp_decode( join ( "", @{$self->{'raw'}} ) ) )
	];
    }
    elsif ( $encoding eq 'base64' ) {
      dbg("decoding: base64");

      # Generate the decoded output
      $self->{'decoded'} = [ Mail::SpamAssassin::Util::base64_decode(join("", @{$self->{'raw'}})) ];

      # If it's a type text or message, split it into an array of lines
      if ( $self->{'type'} =~ m@^(?:text|message)\b/@i ) {
        $self->{'decoded'} = [ map { s/\r\n/\n/; $_; } split(/^/m, $self->{'decoded'}->[0]) ];
      }
    }
    else {
      # Encoding is one of 7bit, 8bit, binary or x-something
      if ( $encoding ) {
        dbg("decoding: other encoding type ($encoding), ignoring");
      }
      else {
        dbg("decoding: no encoding detected");
      }
      $self->{'decoded'} = $self->{'raw'};
    }
  }

  if ( !defined $bytes || $bytes ) {
    my $tmp = join("", @{$self->{'decoded'}});
    if ( !defined $bytes ) {
      return $tmp;
    }
    else {
      return substr($tmp, 0, $bytes);
    }
  }
}

# Look at a text scalar and determine whether it should be rendered
# as text/html.  Based on a heuristic which simulates a certain
# well-used/common mail client.
# 
sub _html_near_start {
  my ($pad) = @_;

  my $count = 0;
  $count += ($pad =~ tr/\n//d) * 2;
  $count += ($pad =~ tr/\n//cd);
  return ($count < 24);
}

=item rendered()

render_text() takes the given text/* type MIME part, and attempt
to render it into a text scalar.  It will always render text/html,
and will use a heuristic to determine if other text/* parts should be
considered text/html.

=cut

sub rendered {
  my ($self) = @_;

  # We don't render anything except text
  return(undef,undef) unless ( $self->{'type'} =~ /^text\b/i );

  if ( !exists $self->{'rendered'} ) {
    my $text = $self->decode();
    my $raw = length($text);

    # render text/html always, or any other text|text/plain part as text/html
    # based on a heuristic which simulates a certain common mail client
    if ( $raw > 0 && (
        $self->{'type'} =~ m@^text/html\b@i || (
        $self->{'type'} =~ m@^text(?:$|/plain)@i &&
	  $text =~ m/^(.{0,18}?<(?:$Mail::SpamAssassin::HTML::re_start)(?:\s.{0,18}?)?>)/ois &&
	  _html_near_start($1))
        )
       ) {
      $self->{'rendered_type'} = 'text/html';
      my $html = Mail::SpamAssassin::HTML->new(); # object
      my @lines = @{$html->html_render($text)};
      $self->{rendered} = join('', @lines);
      $self->{html_results} = $html->get_results(); # needed in eval tests

      # some tests done after rendering
      my $r = $self->{html_results}; # temporary reference for brevity
      my $space = 0;
      $r->{html_length} = 0;
      for my $line (@lines) {
        $line = pack ('C0A*', $line);
        $space += ($line =~ tr/ \t\n\r\x0b\xa0/ \t\n\r\x0b\xa0/);
        $r->{html_length} += length($line);
      }
      $r->{non_space_len} = $r->{html_length} - $space;
      $r->{ratio} = ($raw - $r->{html_length}) / $raw;
      if (exists $r->{total_comment_length} && $r->{html_length} > 0) {
        $r->{total_comment_ratio} = 
	    $r->{total_comment_length} / $r->{html_length};
      }
      if (exists $r->{elements} && exists $r->{tags}) {
	$r->{bad_tag_ratio} = ($r->{tags} - $r->{elements}) / $r->{tags};
	$r->{non_element_ratio} =
	    ($r->{tags_seen} - $r->{elements_seen}) / $r->{tags_seen};
      }
      if (exists $r->{tags} && exists $r->{obfuscation}) {
	$r->{obfuscation_ratio} = $r->{obfuscation} / $r->{tags};
      }
      if (exists $r->{attr_bad} && exists $r->{attr_all}) {
	$r->{attr_bad} = $r->{attr_bad} / $r->{attr_all};
      }
      if (exists $r->{attr_unique_bad} && exists $r->{attr_unique_all}) {
	$r->{attr_unique_bad} = $r->{attr_unique_bad} / $r->{attr_unique_all};
      }
    }
    else {
      $self->{'rendered_type'} = $self->{'type'};
      $self->{'rendered'} = $text;
    }
  }

  return ($self->{'rendered_type'}, $self->{'rendered'});
}

=item content_summary()

Returns an array of scalars describing the mime parts of the message.
Note: This function requires that the message be parsed first via
_do_parse()!

=cut

# return an array with scalars describing mime parts
sub content_summary {
  my($self, $recurse) = @_;

  # go recursive the first time through
  $recurse = 1 unless ( defined $recurse );

  # If this object matches, mark it for return.
  if ( exists $self->{'body_parts'} ) {
    my @ret = ();

    # This object is a subtree root.  Search all children.
    foreach my $parts ( @{$self->{'body_parts'}} ) {
      # Add the recursive results to our results
      my @p = $parts->content_summary(0);
      if ( $recurse ) {
        push(@ret, join(",", @p));
      }
      else {
        push(@ret, @p);
      }
    }

    return($self->{'type'}, @ret);
  }
  else {
    return $self->{'type'};
  }
}

=item delete_header()

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

sub __decode_header {
  my ( $encoding, $cte, $data ) = @_;

  if ( $cte eq 'B' ) {
    # base 64 encoded
    return Mail::SpamAssassin::Util::base64_decode($data);
  }
  elsif ( $cte eq 'Q' ) {
    # quoted printable
    return Mail::SpamAssassin::Util::qp_decode($data);
  }
  else {
    die "Unknown encoding type '$cte' in RFC2047 header";
  }
}

# Decode base64 and quoted-printable in headers according to RFC2047.
#
sub _decode_header {
  my($header) = @_;

  return '' unless $header;

  # deal with folding and cream the newlines and such
  $header =~ s/\n[ \t]+/\n /g;
  $header =~ s/\r?\n//g;

  return $header unless $header =~ /=\?/;

  $header =~
    s/=\?([\w_-]+)\?([bqBQ])\?(.*?)\?=/__decode_header($1, uc($2), $3)/ge;

  return $header;
}

=item get_pristine_header()

=cut


sub get_pristine_header {
  my ($self, $hdr) = @_;
  
  return $self->{pristine_headers} unless $hdr;
  my(@ret) = $self->{pristine_headers} =~ /^(?:$hdr:[ ]+(.*\n(?:\s+\S.*\n)*))/mig;
  if (@ret) {
    return wantarray ? @ret : $ret[-1];
  }
  else {
    return $self->get_header($hdr);
  }
}

=item get_header()

=cut

sub get_header {
  my ($self, $hdr, $raw) = @_;
  $raw ||= 0;

  # And now pick up all the entries into a list
  # This is assumed to include a newline at the end ...
  # This is also assumed to have removed continuation bits ...
  my @hdrs;
  if ( $raw ) {
    @hdrs = map { s/\r?\n\s+/ /g; $_; } $self->raw_header($hdr);
  }
  else {
    @hdrs = map { "$_\n" } $self->header($hdr);
  }

  if (wantarray) {
    return @hdrs;
  }
  else {
    return $hdrs[-1];
  }
}

=item get_all_headers()

=cut

sub get_all_headers {
  my ($self, $raw, $include_mbox) = @_;
  $raw ||= 0;
  $include_mbox ||= 0;

  my %cache = ();
  my @lines = ();

  foreach ( @{$self->{header_order}} ) {
    push(@lines, "$_: ".($self->get_header($_,$raw))[$cache{$_}++]);
  }

  splice @lines, 0, 0, $self->{mbox_sep} if ( $include_mbox && exists $self->{mbox_sep} );

  if (wantarray) {
    return @lines;
  } else {
    return join ('', @lines);
  }
}

sub get_mbox_seperator {
  return $_[0]->{mbox_sep};
}

=item get_body()

=cut

sub get_body {
  my ($self) = @_;
  my @ret = split(/^/m, $self->{pristine_body});
  return \@ret;
}

# ---------------------------------------------------------------------------

=item get_pristine()

=cut

sub get_pristine {
  my ($self) = @_;
  return $self->{pristine_headers} . $self->{pristine_body};
}

=item get_pristine_body()

=cut

sub get_pristine_body {
  my ($self) = @_;
  return $self->{pristine_body};
}

# ---------------------------------------------------------------------------

sub extract_message_metadata {
  my ($self, $main) = @_;

  # do this only once per message, it can be expensive
  if ($self->{already_extracted_metadata}) { return; }
  $self->{already_extracted_metadata} = 1;

  $self->{metadata}->extract ($self, $main);
}

# ---------------------------------------------------------------------------

=item $str = get_metadata($hdr)

=cut

sub get_metadata {
  my ($self, $hdr) = @_;
  $self->{metadata}->{strings}->{$hdr};
}

=item put_metadata($hdr, $text)

=cut

sub put_metadata {
  my ($self, $hdr, $text) = @_;
  $self->{metadata}->{strings}->{$hdr} = $text;
}

=item delete_metadata($hdr)

=cut

sub delete_metadata {
  my ($self, $hdr) = @_;
  delete $self->{metadata}->{strings}->{$hdr};
}

=item $str = get_all_metadata()

=cut

sub get_all_metadata {
  my ($self) = @_;

  my @ret = ();
  foreach my $key (sort keys %{$self->{metadata}->{strings}}) {
    push (@ret, $key, ": ", $self->{metadata}->{strings}->{$key}, "\n");
  }
  return join ("", @ret);
}

# ---------------------------------------------------------------------------

=item finish_metadata()

Destroys the metadata for this message.  Once a message has been
scanned fully, the metadata is no longer required.   Destroying
this will free up some memory.

=cut

sub finish_metadata {
  my ($self) = @_;
  if ($self->{metadata}) {
    $self->{metadata}->finish();
    delete $self->{metadata};
  }
}

=item finish()

Clean up an object so that it can be destroyed.

=cut

sub finish {
  my ($self) = @_;
  $self->finish_metadata();
}

# ---------------------------------------------------------------------------

sub dbg { Mail::SpamAssassin::dbg (@_); }

1;
__END__
