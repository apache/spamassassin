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
use bytes;

use Mail::SpamAssassin;
use Mail::SpamAssassin::Constants qw(:sa);
use Mail::SpamAssassin::HTML;
use Mail::SpamAssassin::Logger;

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
    body_parts		=> [],
    header_order	=> []
  };

  # deal with any parameters
  my($opts) = @_;
  if (defined $opts->{'subparse'}) {
    $self->{subparse} = $opts->{'subparse'};
  }

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
# objects which match.
#
sub find_parts {
  my ($self, $re, $onlyleaves, $recursive) = @_;

  # Didn't pass an RE?  Just abort.
  return () unless $re;

  $onlyleaves = 0 unless defined $onlyleaves;

  my $depth;
  if (defined $recursive && $recursive == 0) {
    $depth = 1;
  }
  
  return $self->_find_parts($re, $onlyleaves, $depth);
}

# We have 2 functions in find_parts() to optimize out the penalty of
# $onlyleaves, $re, and $recursive over and over again.
#
sub _find_parts {
  my ($self, $re, $onlyleaves, $depth) = @_;
  my @ret = ();

  # If this object matches, mark it for return.
  my $amialeaf = $self->is_leaf();

  if ( $self->{'type'} =~ /$re/ && (!$onlyleaves || $amialeaf) ) {
    push(@ret, $self);
  }
  
  if ( !$amialeaf && (!defined $depth || $depth > 0)) {
    $depth-- if defined $depth;

    # This object is a subtree root.  Search all children.
    foreach my $parts ( @{$self->{'body_parts'}} ) {
      # Add the recursive results to our results
      push(@ret, $parts->_find_parts($re, $onlyleaves, $depth));
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

  return unless ( defined $rawkey );

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
  return $_[0]->{'raw'};
}

=item decode()

If necessary, decode the part text as base64 or quoted-printable.
The decoded text will be returned as a scalar.  An optional length
parameter can be passed in which limits how much decoded data is returned.
If the scalar isn't needed, call with "0" as a parameter.

=cut

sub decode {
  my($self, $bytes) = @_;

  if ( !exists $self->{'decoded'} ) {
    my $encoding = lc $self->header('content-transfer-encoding') || '';

    if ( $encoding eq 'quoted-printable' ) {
      dbg("message: decoding quoted-printable");
      $self->{'decoded'} = [
        map { s/\r\n/\n/; $_; } split ( /^/m, Mail::SpamAssassin::Util::qp_decode( join ( "", @{$self->{'raw'}} ) ) )
	];
    }
    elsif ( $encoding eq 'base64' ) {
      dbg("message: decoding base64");

      # if it's not defined or is 0, do the whole thing, otherwise only decode
      # a portion
      if ($bytes) {
        return Mail::SpamAssassin::Util::base64_decode(join("", @{$self->{'raw'}}), $bytes);
      }
      else {
        # Generate the decoded output
        $self->{'decoded'} = [ Mail::SpamAssassin::Util::base64_decode(join("", @{$self->{'raw'}})) ];
      }

      # If it's a type text or message, split it into an array of lines
      if ( $self->{'type'} =~ m@^(?:text|message)\b/@i ) {
        $self->{'decoded'} = [ map { s/\r\n/\n/; $_; } split(/^/m, $self->{'decoded'}->[0]) ];
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

=item rendered()

render_text() takes the given text/* type MIME part, and attempts to
render it into a text scalar.  It will always render text/html, and will
use a heuristic to determine if other text/* parts should be considered
text/html.  Two scalars are returned: the rendered type (either text/html
or whatever the original type was), and the rendered text.

=cut

sub rendered {
  my ($self) = @_;

  # We don't render anything except text
  return(undef,undef) unless ( $self->{'type'} =~ /^text\b/i );

  if (!exists $self->{rendered}) {
    my $text = $self->decode();
    my $raw = length($text);

    # render text/html always, or any other text|text/plain part as text/html
    # based on a heuristic which simulates a certain common mail client
    if ($raw > 0 && ($self->{'type'} =~ m@^text/html\b@i ||
		     ($self->{'type'} =~ m@^text(?:$|/plain)@i &&
		      _html_render(substr($text, 0, 23)))))
    {
      $self->{rendered_type} = 'text/html';

      my $html = Mail::SpamAssassin::HTML->new();	# object
      $html->parse($text);				# parse+render text
      $self->{rendered} = $html->get_rendered_text();
      $self->{visible_rendered} = $html->get_rendered_text(invisible => 0);
      $self->{invisible_rendered} = $html->get_rendered_text(invisible => 1);
      $self->{html_results} = $html->get_results();

      # end-of-document result values that require looking at the text
      my $r = $self->{html_results};	# temporary reference for brevity

      # count the number of spaces in the rendered text
      my $rt = pack "C0A*", $self->{rendered};
      my $space = ($rt =~ tr/ \t\n\r\x0b\xa0/ \t\n\r\x0b\xa0/);
      $r->{html_length} = length($rt);

      $r->{non_space_len} = $r->{html_length} - $space;
      $r->{ratio} = ($raw - $r->{html_length}) / $raw;
    }
    else {
      $self->{rendered_type} = $self->{type};
      $self->{rendered} = $text;
    }
  }

  return ($self->{rendered_type}, $self->{rendered});
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
  my ( $encoding, $cte, $data ) = @_;

  if ( $cte eq 'B' ) {
    # base 64 encoded
    return Mail::SpamAssassin::Util::base64_decode($data);
  }
  elsif ( $cte eq 'Q' ) {
    # quoted printable

    # the RFC states that in the encoded text, "_" is equal to "=20"
    $data =~ s/_/=20/g;

    return Mail::SpamAssassin::Util::qp_decode($data);
  }
  else {
    # not possible since the input has already been limited to 'B' and 'Q'
    die "message: unknown encoding type '$cte' in RFC2047 header";
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

  # multiple encoded sections must ignore the interim whitespace.
  # to avoid possible FPs with (\s+(?==\?))?, look for the whole RE
  # separated by whitespace.
  1 while ($header =~ s/(=\?[\w_-]+\?[bqBQ]\?[^?]+\?=)\s+(=\?[\w_-]+\?[bqBQ]\?[^?]+\?=)/$1$2/g);

  $header =~
    s/=\?([\w_-]+)\?([bqBQ])\?([^?]+)\?=/__decode_header($1, uc($2), $3)/ge;

  return $header;
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

=cut

# TODO: this could be made much faster by only processing all headers
# when called in array context, otherwise just do one header
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
      @hdrs = map { s/\r?\n\s+/ /g; $_; } @hdrs;
    }
  }
  else {
    if (@hdrs = $self->header($hdr)) {
      @hdrs = map { "$_\n" } @hdrs;
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

=cut

# build it and it will not bomb
sub get_all_headers {
  my ($self, $raw, $include_mbox) = @_;
  $raw ||= 0;
  $include_mbox ||= 0;

  my @lines = ();

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
      $lines[$position] = $self->{header_order}->[$position] . ": $contents";
    }
  }

  # skip undefined lines if we truncated
  @lines = grep { defined $_ } @lines if $self->{'truncated_header'};

  splice @lines, 0, 0, $self->{mbox_sep} if ( $include_mbox && exists $self->{mbox_sep} );

  return wantarray ? @lines : join ('', @lines);
}

# ---------------------------------------------------------------------------

=item finish()

Clean up the object so that it can be destroyed.

=cut

sub finish {
  my ($self) = @_;

  # Clean up ourself
  undef $self->{'headers'};
  undef $self->{'raw_headers'};
  undef $self->{'header_order'};
  undef $self->{'raw'};
  undef $self->{'decoded'};
  undef $self->{'rendered'};
  undef $self->{'visible_rendered'};
  undef $self->{'invisible_rendered'};
  undef $self->{'type'};
  undef $self->{'rendered_type'};

  # Clean up our kids
  if (exists $self->{'body_parts'}) {
    while ( my $part = shift @{$self->{'body_parts'}} ) {
      $part->finish();
    }
    undef $self->{'body_parts'};
  }
}

# ---------------------------------------------------------------------------

1;
__END__
