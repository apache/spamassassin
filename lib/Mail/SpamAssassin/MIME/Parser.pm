# $Id: Parser.pm,v 1.15 2003/10/01 04:36:21 felicity Exp $

package Mail::SpamAssassin::MIME::Parser;
use strict;

# MIME Message parser, for email and nntp engines.

use Mail::SpamAssassin;
use Mail::SpamAssassin::MIME;
use MIME::Base64;
use MIME::QuotedPrint;

=head2 This is how mail messages can come in:

=over 4

=item 1. Plain text

Plain text messages come in with a content-type of text/plain. They
may contain attachments as UU Encoded strings.

=item 2. HTML text

Straight HTML messages come in with a content-type of text/html. They
may not contain attachments as far as I'm aware.

=item 3. Mixed text, html and maybe other.

These messages come in as MIME messages with the content-type of
multipart/alternative (alternate means you get to pick which view of the
message to display, as all must contain the same basic information).

There may not be attachments this way as far as I'm aware.

=item 4. Plain text with attachments

Here the content-type is multipart/mixed. The first part of the multipart
message is the the plain
 text message (after the preamble, that is), with
a content type of text/plain. The remaining parts are attachments.

=item 5. HTML text with attachments

Again, the content-type is multipart/mixed. The first part of the multipart
message is the html message, with a content-type of text/html. The
remaining parts are attachments.

=item 6. Mixed text, html with attachments

Here the main part of the message has a content-type of multipart/mixed. The
first part has a content-type of multipart/alternative, and is identical to
item 3 above. The remaining parts are the attachments.

=item 7. Report.

This is a delivery status report. It comes with the main part of the message
having a content-type of multipart/report, the first one or two parts of which
may be textual content of some sort, and the last seems to be of type
message/rfc822. 

=back

Overall this is a fairly naive way to view email messages, as the
attachments can be email messages themselves, and thus it gets very
recursive. But this should be enough for us to deal with right now.

=cut

# constructor
sub parse {
  my($self,$message) = @_;

  # now go generate stuff
  my @message = split ( /^/m, $message );
  shift @message if ( $message[0] =~ /^From\s/ );    # trim mbox seperator
  my $msg = Mail::SpamAssassin::MIME->new();

  local $_;                                          # protect from abuse

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
      if ( $key =~ /^(?:MIME-Version|Lines|X-MIME|Content-)/i ) {
        $msg->header( $key, $self->decode_header($value), $value );
      }
    }

    # not a continuation...
    $header = $last;

    last if ( $last =~ /^$/m );
  }

  # Parse out the body ...
  my ($boundary) =
    $msg->header('content-type') =~ /boundary\s*=\s*["']?([^"';]+)["']?/i;
  $self->parse_body( $msg, $msg, $boundary, \@message );

  return $msg;
}

sub parse_body {
  my($self, $msg, $_msg, $boundary, $body) = @_;

  # CRLF -> LF
  for ( @{$body} ) {
    s/\r\n/\n/;
  }

  my $type = $_msg->header('Content-Type') || 'text/plain; charset=us-ascii';

  #    warn "Parsing message of type: $type\n";

  if ( $type =~ /^text\/plain/i ) {
    dbg("Parse text/plain\n");
    $self->parse_normal( $msg, $_msg, $boundary, $body );
  }
  elsif ( $type =~ /^text\/html/i ) {
    dbg("Parse text/html\n");
    $self->parse_normal( $msg, $_msg, $boundary, $body );
  }
  elsif ( $type =~ /^multipart\/alternative/i ) {
    dbg("Parse multipart/alternative\n");
    $self->parse_multipart_alternate( $msg, $_msg, $boundary, $body );
  }
  elsif ( $type =~ /^multipart\//i ) {
    dbg("Parse $type\n");
    $self->parse_multipart_mixed( $msg, $_msg, $boundary, $body );
  }
  else {
    dbg("Regular attachment\n");
    $self->decode_body( $msg, $_msg, $boundary, $body );
  }

  if ( !$msg->body() ) {
    dbg("No message body found. Reparsing as blank.\n");
    my $part_msg = Mail::SpamAssassin::MIME->new();
    $self->decode_body( $msg, $part_msg, $boundary, [] );
  }
}

sub parse_multipart_alternate {
  my($self, $msg, $_msg, $boundary, $body ) = @_;

  dbg("m/a got boundary: $boundary\n");

  # ignore preamble per RFC 1521
  while ( my $line = shift @{$body} ) {
    last if $line =~ /^\-\-\Q$boundary\E$/;
  }

  my $in_body = 0;

  my $header;
  my $part_array;
  my $part_msg = Mail::SpamAssassin::MIME->new();

  my $line_count = @{$body};
  foreach ( @{$body} ) {
    if ( --$line_count == 0 || /^\-\-\Q$boundary\E/ ) {
      dbg("m/a got end of section\n");

      # end of part
      my $line = $_;

      # per rfc 1521, the CRLF before the boundary is part of the boundary ...
      if ($part_array) {
        chomp( $part_array->[ scalar @{$part_array} - 1 ] );
        splice @{$part_array}, -1
          if ( $part_array->[ scalar @{$part_array} - 1 ] eq '' );

        $self->decode_body( $msg, $part_msg, $boundary, $part_array );
      }

      last if $line =~ /^\-\-\Q$boundary\E\-\-$/;
      $in_body  = 0;
      $part_msg = Mail::SpamAssassin::MIME->new();
      undef $part_array;
      next;
    }

    if ($in_body) {
      push ( @{$part_array}, $_ );
    }
    else {

      # chomp($_);
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

sub parse_multipart_mixed {
  my($self, $msg, $_msg, $boundary, $body) = @_;

  dbg("m/m Got boundary: $boundary\n");

  # ignore preamble per RFC 1521
  while ( my $line = shift @{$body} ) {
    last if $line =~ /^\-\-\Q$boundary\E$/;
  }

  my $part_msg =
    Mail::SpamAssassin::MIME->new();    # just used for headers storage
  my $in_body = 0;

  my $header;
  my $part_array;

  my $line_count = @{$body};
  foreach ( @{$body} ) {
    if ( --$line_count == 0 || /^\-\-\Q$boundary\E/ ) {

      # end of part
      dbg("Got end of MIME section: $_\n");
      my $line = $_;

      # per rfc 1521, the CRLF before the boundary is part of the boundary ...
      if ($part_array) {
        chomp( $part_array->[ scalar @{$part_array} - 1 ] );
        splice @{$part_array}, -1
          if ( $part_array->[ scalar @{$part_array} - 1 ] eq '' );

        my ($p_boundary) =
          $part_msg->header('content-type') =~
          /boundary\s*=\s*["']?([^"';]+)["']?/i;
        $p_boundary ||= $boundary;
        $self->parse_body( $msg, $part_msg, $p_boundary, $part_array );
      }

      last if $line =~ /^\-\-\Q${boundary}\E\-\-$/;
      $in_body  = 0;
      $part_msg = Mail::SpamAssassin::MIME->new();
      undef $part_array;
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

sub parse_normal {
  my($self, $msg, $_msg, $boundary, $body) = @_;

  # extract body, store it in $msg
  $self->decode_body( $msg, $_msg, $boundary, $body );
}

sub _decode_header {
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

# decode according to RFC2047
sub decode_header {
  my($self, $header) = @_;

  return '' unless $header;
  return $header unless $header =~ /=\?/;

  $header =~
    s/=\?([\w_-]+)\?([bqBQ])\?(.*?)\?=/_decode_header($1, uc($2), $3)/ge;
  return $header;
}

sub decode_body {
  my($self, $msg, $part_msg, $boundary, $body ) = @_;

  dbg("decoding attachment\n");

  my ( $type, $content, $filename ) = $self->decode( $part_msg, $body );

  my $opts = {
  	decoded => $content,
	raw => $body,
	boundary => $boundary,
	headers => $part_msg->{headers},
	raw_headers => $part_msg->{raw_headers},
  };
  $opts->{name} = $filename if ( $filename );

  $msg->add_body_part( $type, $opts );
}

sub decode {
  my($self, $msg, $body ) = @_;

  if ( lc( $msg->header('content-transfer-encoding') ) eq 'quoted-printable' ) {
    dbg("decoding QP file\n");
    my @output =
      map { s/\r\n/\n/; $_; } split ( /^/m, Mail::SpamAssassin::Util::qp_decode( join ( "", @{$body} ) ) );

    my $type = $msg->header('content-type');
    my ($filename) =
      ( $msg->header('content-disposition') =~ /name="?([^\";]+)"?/i );
    if ( !$filename ) {
      ($filename) = ( $type =~ /name="?([^\";]+)"?/i );
    }

    return $type, \@output, $filename;
  }
  elsif ( lc( $msg->header('content-transfer-encoding') ) eq 'base64' ) {
    dbg("decoding B64 file\n");

    # Generate the decoded output
    my $output = [ Mail::SpamAssassin::Util::base64_decode(join("", @{$body})) ];

    # If it has a filename, figure it out.
    my $type = $msg->header('content-type');
    my ($filename) =
      ( $msg->header('content-disposition') =~ /name="?([^\";]+)"?/i );
    if ( !$filename ) {
      ($filename) = ( $type =~ /name="?([^\";]+)"?/i );
    }

    # If it's a type text or message, split it into an array of lines
    $output = [ map { s/\r\n/\n/; $_; } split(/^/m, $output->[0]) ] if ( $type =~ m@^(?:text|message)/@ );

    return $type, $output, $filename;
  }
  else {
    # Encoding is one of 7bit, 8bit, binary or x-something
    dbg("decoding other encoding\n");

    my $type = $msg->header('content-type');
    my ($filename) =
      ( $msg->header('content-disposition') =~ /name="?([^\";]+)"?/i );
    if ( !$filename ) {
      ($filename) = ( $type =~ /name="?([^\";]+)"?/i );
    }

    # No encoding, so just point to the raw data ...
    return $type, $body, $filename;
  }
}

sub dbg { Mail::SpamAssassin::dbg (@_); }

1;
__END__
