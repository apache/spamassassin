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

Mail::SpamAssassin::MsgParser - parse and store MIME formatted messages

=head1 SYNOPSIS

=head1 DESCRIPTION

This module will take a RFC2822-esque formatted message and create
an object with all of the MIME body parts included.  Those parts will
be decoded as necessary, and text/html parts will be rendered into a
standard text format, suitable for use in SpamAssassin.

=head1 PUBLIC METHODS

=over 4

=cut

package Mail::SpamAssassin::MsgParser;
use strict;

use Mail::SpamAssassin;
use Mail::SpamAssassin::MsgContainer;

use constant MAX_BODY_LINE_LENGTH =>        2048;

=item parse()

Unlike most modules, Mail::SpamAssassin::MsgParser will not return
an object of the same type, but rather a Mail::SpamAssassin::MsgContainer
object.  To use it, simply call
C<Mail::SpamAssassin::MsgParser->parse($msg)>, where $msg is either
a scalar, an array reference, or a glob, with the entire contents
of the mesage.

The procedure used to parse a message is recursive and ends up generating
a tree of M::SA::MsgContainer objects.  parse() will generate the parent node
of the tree, then pass the body of the message to _parse_body() which begins
the recursive process.

=cut

sub parse {
  my($self,$message) = @_;
  $message ||= \*STDIN;

  dbg("---- MIME PARSER START ----");

  # protect it from abuse ...
  local $_;

  my @message;
  if (ref $message eq 'ARRAY') {
     @message = @{$message};
  }
  elsif (ref $message eq 'GLOB') {
    if (defined fileno $message) {
      @message = <$message>;
    }
  }
  else {
    @message = split ( /^/m, $message );
  }

  # Generate the main object and parse the appropriate MIME-related headers into it.
  my $msg = Mail::SpamAssassin::MsgContainer->new();
  my $header = '';

  # Go through all the headers of the message
  while ( my $last = shift @message ) {
    # Store the non-modified headers in a scalar
    $msg->{'pristine_headers'} .= $last;

    if ( $last =~ /^From\s/ ) {
      $msg->{'mbox_sep'} = $last;
      next;
    }

    # NB: Really need to figure out special folding rules here!
    if ( $last =~ /^[ \t]+/ ) {                    # if its a continuation
      $header .= $last;                            # fold continuations
      next;
    }

    # Ok, there's a header here, let's go ahead and add it in.
    if ($header) {
      my ( $key, $value ) = split ( /:\s*/, $header, 2 );
      $msg->header( $key, $value );
    }

    # not a continuation...
    $header = $last;

    # Ok, we found the header/body blank line ...
    last if ( $last =~ /^\r?$/m );
  }

  # Store the pristine body for later -- store as a copy since @message will get modified below
  $msg->{'pristine_body'} = join('', @message);

  # Figure out the boundary
  my ($boundary);
  ($msg->{'type'}, $boundary) = Mail::SpamAssassin::Util::parse_content_type($msg->header('content-type'));
  dbg("main message type: ".$msg->{'type'});

  # Make the tree
  $self->_parse_body( $msg, $msg, $boundary, \@message, 1 );

  dbg("---- MIME PARSER END ----");

  return $msg;
}

=head1 NON-PUBLIC METHODS

=item _parse_body()

_parse_body() passes the body part that was passed in onto the
correct part parser, either _parse_multipart() for multipart/* parts,
or _parse_normal() for everything else.  Multipart sections become the
root of sub-trees, while everything else becomes a leaf in the tree.

For multipart messages, the first call to _parse_body() doesn't create a
new sub-tree and just uses the parent node to contain children.  All other
calls to _parse_body() will cause a new sub-tree root to be created and
children will exist underneath that root.  (this is just so the tree
doesn't have a root node which points at the actual root node ...)

=cut

sub _parse_body {
  my($self, $msg, $_msg, $boundary, $body, $initial) = @_;

  # CRLF -> LF
  for ( @{$body} ) {
    s/\r\n/\n/;
  }

  # Figure out the simple content-type, or set it to text/plain
  my $type = $_msg->header('Content-Type') || 'text/plain; charset=us-ascii';

  # multipart sections are required to have a boundary set ...  If this
  # one doesn't, assume it's malformed and send it to be parsed as a
  # non-multipart section
  #
  if ( $type =~ /^multipart\//i && defined $boundary ) {
    # Treat an initial multipart parse differently.  This will keep the tree:
    # obj(multipart->[ part1, part2 ]) instead of
    # obj(obj(multipart ...))
    #
    if ( $initial ) {
      $self->_parse_multipart( $msg, $_msg, $boundary, $body );
    }
    else {
      $self->_parse_multipart( $_msg, $_msg, $boundary, $body );
      $msg->add_body_part( $_msg );
    }
  }
  else {
    # If it's not multipart, go ahead and just deal with it.
    $self->_parse_normal( $msg, $_msg, $boundary, $body );
  }
}

=item _parse_multipart()

Generate a root node, and for each child part call _parse_body()
to generate the tree.

=cut

sub _parse_multipart {
  my($self, $msg, $_msg, $boundary, $body) = @_;

  dbg("parsing multipart, got boundary: ".(defined $boundary ? $boundary : ''));

  # ignore preamble per RFC 1521, unless there's no boundary ...
  if ( defined $boundary ) {
    my $line;
    my $tmp_line = @{$body};
    for ($line=0; $line < $tmp_line; $line++) {
      last if $body->[$line] =~ /^\-\-\Q$boundary\E$/;
    }

    # Found a boundary, ignore the preamble
    if ( $line < $tmp_line ) {
      splice @{$body}, 0, $line+1;
    }

    # Else, there's no boundary, so leave the whole part...
  }

  my $part_msg = Mail::SpamAssassin::MsgContainer->new();    # prepare a new tree node
  my $in_body = 0;
  my $header;
  my $part_array;

  my $line_count = @{$body};
  foreach ( @{$body} ) {
    # if we're on the last body line, or we find a boundary marker, deal with the mime part
    if ( --$line_count == 0 || (defined $boundary && /^\-\-\Q$boundary\E/) ) {
      my $line = $_; # remember the last line

      # per rfc 1521, the CRLF before the boundary is part of the boundary:
      # NOTE: The CRLF preceding the encapsulation line is conceptually
      # attached to the boundary so that it is possible to have a part
      # that does not end with a CRLF (line break). Body parts that must
      # be considered to end with line breaks, therefore, must have two
      # CRLFs preceding the encapsulation line, the first of which is part
      # of the preceding body part, and the second of which is part of the
      # encapsulation boundary.
      if ($part_array) {
        chomp( $part_array->[-1] );  # trim the CRLF that's part of the boundary
        splice @{$part_array}, -1 if ( $part_array->[-1] eq '' ); # blank line for the boundary only ...

        my($p_boundary);
	($part_msg->{'type'}, $p_boundary) = Mail::SpamAssassin::Util::parse_content_type($part_msg->header('content-type'));
        $p_boundary ||= $boundary;
	dbg("found part of type ".$part_msg->{'type'}.", boundary: ".(defined $p_boundary ? $p_boundary : ''));
        $self->_parse_body( $msg, $part_msg, $p_boundary, $part_array, 0 );
      }

      last if (defined $boundary && $line =~ /^\-\-\Q${boundary}\E\-\-$/);

      # make sure we start with a new clean node
      $in_body  = 0;
      $part_msg = Mail::SpamAssassin::MsgContainer->new();
      undef $part_array;
      undef $header;

      next;
    }

    if ($in_body) {
      # we run into a perl bug if the lines are astronomically long (probably due
      # to lots of regexp backtracking); so cut short any individual line over
      # MAX_BODY_LINE_LENGTH bytes in length.  This can wreck HTML totally -- but
      # IMHO the only reason a luser would use MAX_BODY_LINE_LENGTH-byte lines is
      # to crash filters, anyway.
      while (length ($_) > MAX_BODY_LINE_LENGTH) {
        push (@{$part_array}, substr($_, 0, MAX_BODY_LINE_LENGTH)."\n");
        substr($_, 0, MAX_BODY_LINE_LENGTH) = '';
      }
      push ( @{$part_array}, $_ );
    }
    else {
      s/\s+$//;
      if (m/^\S/) {
        if ($header) {
          my ( $key, $value ) = split ( /:\s*/, $header, 2 );
          $part_msg->header( $key, $value );
        }
        $header = $_;
      }
      elsif (/^$/) {
        if ($header) {
          my ( $key, $value ) = split ( /:\s*/, $header, 2 );
          $part_msg->header( $key, $value );
        }
        $in_body = 1;
      }
      else {
        $_ =~ s/^\s*//;
        $header .= $_;
      }
    }
  }

}

=item _parse_normal()

Generate a leaf node and add it to the parent.

=cut

sub _parse_normal {
  my ($self, $msg, $part_msg, $boundary, $body) = @_;

  dbg("parsing normal part");

  $part_msg->{'type'} =
    Mail::SpamAssassin::Util::parse_content_type($part_msg->header('content-type'));

  # multipart sections are required to have a boundary set ...  If this
  # one doesn't, assume it's malformed and revert to text/plain
  $part_msg->{'type'} = 'text/plain' if ( $part_msg->{'type'} =~ /^multipart\//i && !defined $boundary );

  # attempt to figure out a name for this attachment if there is one ...
  my $disp = $part_msg->header('content-disposition') || '';
  my($filename) = $disp =~ /name="?([^\";]+)"?/i || $part_msg->{'type'} =~ /name="?([^\";]+)"?/i;

  $part_msg->{'raw'} = $body;
  $part_msg->{'boundary'} = $boundary;
  $part_msg->{'name'} = $filename if $filename;

  $msg->add_body_part($part_msg);

  # now that we've added the leaf node, let's go ahead and kill
  # body_parts (used for sub-trees).  it could end up being recursive,
  # and well, let's avoid that. ;)
  #
  # BTW: please leave this after add_body_parts() since it'll add it back.
  #
  delete $part_msg->{body_parts};
}

sub dbg { Mail::SpamAssassin::dbg (@_); }

1;
__END__

=back

=head1 SEE ALSO

C<Mail::SpamAssassin>
C<Mail::SpamAssassin::MsgContainer>
C<spamassassin>

