=head1 NAME

Mail::SpamAssassin::MIME::Parser - parse, decode, and render MIME body parts

=head1 SYNOPSIS

=head1 DESCRIPTION

This module will take a RFC2822-esque formatted message and create
an object with all of the MIME body parts included.  Those parts will
be decoded as necessary, and text/html parts will be rendered into a
standard text format, suitable for use in SpamAssassin.

=head1 METHODS

=over 4

=cut

package Mail::SpamAssassin::MIME::Parser;
use strict;

use Mail::SpamAssassin;
use Mail::SpamAssassin::MIME;
use Mail::SpamAssassin::HTML;
use MIME::Base64;
use MIME::QuotedPrint;

=item parse()

Unlike most modules, Mail::SpamAssassin::MIME::Parser will not return an
object of the same type, but rather a Mail::SpamAssassin::MIME object.
To use it, simply call C<Mail::SpamAssassin::MIME::Parser->parse($msg)>,
where $msg is a scalar with the entire contents of the mesage.

The procedure used to parse a message is recursive and ends up generating
a tree of M::SA::MIME objects.  parse() will generate the parent node
of the tree, then pass the body of the message to _parse_body() which begins
the recursive process.

This is the only public method available!

=cut

sub parse {
  my($self,$message) = @_;

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

  # trim mbox seperator if it exists
  shift @message if ( scalar @message > 0 && $message[0] =~ /^From\s/ );

  # Generate the main object and parse the appropriate MIME-related headers into it.
  my $msg = Mail::SpamAssassin::MIME->new();
  my $header = '';

  while ( my $last = shift @message ) {
    $last =~ s/\r\n/\n/;
    chomp($last);

    # NB: Really need to figure out special folding rules here!
    if ( $last =~ s/^[ \t]+// ) {                    # if its a continuation
      $header .= " $last";                           # fold continuations
      next;
    }

    if ($header) {
      my ( $key, $value ) = split ( /:\s*/, $header, 2 );
      $msg->header( $key, $self->_decode_header($value), $value );
    }

    # not a continuation...
    $header = $last;

    last if ( $last =~ /^$/m );
  }

  my ($boundary);
  ($msg->{'type'}, $boundary) = Mail::SpamAssassin::Util::parse_content_type($msg->header('content-type'));
  dbg("main message type: ".$msg->{'type'});

  # Make the tree
  $self->_parse_body( $msg, $msg, $boundary, \@message, 1 );

  dbg("---- MIME PARSER END ----");

  return $msg;
}

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

  if ( $type =~ /^multipart\//i ) {
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

Generate a root node, and for each child part call _parse_body().

=cut

sub _parse_multipart {
  my($self, $msg, $_msg, $boundary, $body) = @_;

  $boundary ||= '';
  dbg("parsing multipart, got boundary: $boundary");

  # ignore preamble per RFC 1521, unless there's no boundary ...
  if ( $boundary ) {
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

  my $part_msg = Mail::SpamAssassin::MIME->new();    # prepare a new tree node
  my $in_body = 0;
  my $header;
  my $part_array;

  my $line_count = @{$body};
  foreach ( @{$body} ) {
    # if we're on the last body line, or we find a boundary marker, deal with the mime part
    if ( --$line_count == 0 || ($boundary && /^\-\-\Q$boundary\E/) ) {
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
	dbg("found part of type ".$part_msg->{'type'}.", boundary: ".$p_boundary);
        $self->_parse_body( $msg, $part_msg, $p_boundary, $part_array, 0 );
      }

      last if ($boundary && $line =~ /^\-\-\Q${boundary}\E\-\-$/);

      # make sure we start with a new clean node
      $in_body  = 0;
      $part_msg = Mail::SpamAssassin::MIME->new();
      undef $part_array;
      undef $header;

      next;
    }

    if ($in_body) {
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

=item _decode_header()

Decode base64 and quoted-printable in headers according to RFC2047.

=cut

sub _decode_header {
  my($self, $header) = @_;

  return '' unless $header;
  return $header unless $header =~ /=\?/;

  $header =~
    s/=\?([\w_-]+)\?([bqBQ])\?(.*?)\?=/__decode_header($1, uc($2), $3)/ge;
  return $header;
}

sub dbg { Mail::SpamAssassin::dbg (@_); }

1;
__END__

=back

=head1 SEE ALSO

C<Mail::SpamAssassin>
C<spamassassin>

