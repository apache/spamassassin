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
    metadata		=> {},
    body_parts		=> [],
    header_order	=> [],
    };

  foreach ( 'noexit' ) {
    $self->{$_} = $opts{$_} if ( exists $opts{$_} );
  }

  bless($self,$class);

  $self;
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
  my @ret = ();

  # If this object matches, mark it for return.
  my $amialeaf = !exists $self->{'body_parts'};

  if ( $self->{'type'} =~ /$re/ && (!$onlyleaves || $amialeaf) ) {
    push(@ret, $self);
  }
  
  if ( $recursive && !$amialeaf ) {
    # This object is a subtree root.  Search all children.
    foreach my $parts ( @{$self->{'body_parts'}} ) {
      # Add the recursive results to our results
      push(@ret, $parts->find_parts($re));
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

=item is_root()

=cut

sub is_root {
  return ! exists $_[0]->{'raw'};
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

    # render text/html always, or any other text|text/plain part as text/html based
    # on a heuristic which simulates a certain common mail client
    if ( $raw > 0 && (
        $self->{'type'} =~ m@^text/html\b@i || (
        $self->{'type'} =~ m@^text(?:$|/plain)@i &&
	  $text =~ m/^(.{0,18}?<(?:$Mail::SpamAssassin::HTML::re_start)(?:\s.{0,18}?)?>)/ois &&
	  _html_near_start($1))
        )
       ) {
      $self->{'rendered_type'} = 'text/html';
      my $html = Mail::SpamAssassin::HTML->new();		# object
      my @lines = @{$html->html_render($text)};
      $self->{rendered} = join('', @{$html->html_render($text)});	# rendered text
      $self->{html_results} = $html->get_results();		# needed in eval tests

      my $space = 0;
      $self->{html_results}{non_uri_len} = 0;
      for my $line (@lines) {
        $line = pack ('C0A*', $line);
        $space += ($line =~ tr/ \t\n\r\x0b\xa0/ \t\n\r\x0b\xa0/);
        $self->{html_results}{non_uri_len} += length($line);
        for my $uri ($line =~ m/\b(URI:\S+)/g) {
          $self->{html_results}{non_uri_len} -= length($uri);
        }
      }
      $self->{html_results}{non_space_len} = $self->{html_results}{non_uri_len} - $space;
      $self->{html_results}{ratio} = ($raw - $self->{html_results}{non_uri_len}) / $raw;
      if (exists $self->{html_results}{total_comment_length} && $self->{html_results}{non_uri_len} > 0) {
        $self->{html_results}{total_comment_ratio} = $self->{html_results}{total_comment_length} / $self->{html_results}{non_uri_len};
      }
      if (exists $self->{html_results}{elements} &&
	  exists $self->{html_results}{tags})
      {
	$self->{html_results}{t_bad_tag_ratio} = ($self->{html_results}{tags} - $self->{html_results}{elements}) / $self->{html_results}{tags};
	$self->{html_results}{t_bad_tag_count} = ($self->{html_results}{tags} - $self->{html_results}{elements});
	$self->{html_results}{t_bad_tag_unique_ratio} = ($self->{html_results}{tags_seen} - $self->{html_results}{elements_seen}) / $self->{html_results}{tags_seen};
	$self->{html_results}{t_bad_tag_unique_count} = ($self->{html_results}{tags_seen} - $self->{html_results}{elements_seen});
      }
      if (exists $self->{html_results}{tags} &&
	  exists $self->{html_results}{obfuscation})
      {
	$self->{html_results}{obfuscation_ratio} = $self->{html_results}{obfuscation} / $self->{html_results}{tags};
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
  my ($self, $raw) = @_;
  $raw ||= 0;

  my %cache = ();
  my @lines = ();

  foreach ( @{$self->{header_order}} ) {
    push(@lines, "$_: ".($self->get_header($_,$raw))[$cache{$_}++]);
  }

  if (wantarray) {
    return @lines;
  } else {
    return join ('', @lines);
  }
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

=item ignore()

=cut

sub ignore {
  my ($self) = @_;
  exit (0) unless $self->{noexit};
}

# ---------------------------------------------------------------------------

=item $str = get_metadata($hdr)

=cut

sub get_metadata {
  my ($self, $hdr) = @_;
  $self->{metadata}->{$hdr};
}

=item put_metadata($hdr, $text)

=cut

sub put_metadata {
  my ($self, $hdr, $text) = @_;
  $self->{metadata}->{$hdr} = $text;
}

=item delete_metadata($hdr)

=cut

sub delete_metadata {
  my ($self, $hdr) = @_;
  delete $self->{metadata}->{$hdr};
}

=item $str = get_all_metadata()

=cut

sub get_all_metadata {
  my ($self) = @_;

  my @ret = ();
  foreach my $key (sort keys %{$self->{metadata}}) {
    push (@ret, $key, ": ", $self->{metadata}->{$key}, "\n");
  }
  return join ("", @ret);
}

# ---------------------------------------------------------------------------

sub dbg { Mail::SpamAssassin::dbg (@_); }

1;
__END__
