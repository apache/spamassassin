# $Id: Parser.pm,v 1.1 2003/09/24 06:18:38 felicity Exp $

package Mail::SpamAssassin::MIME::Parser;
use strict;

# MIME Message parser, for email and nntp engines.

use Mail::SpamAssassin::MIME;
use MIME::Base64;
use MIME::QuotedPrint;
use Carp;

sub debug {

  # warn((caller)[2], @_);
}

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
  my $class   = shift;
  my $message = shift;

  # now go generate stuff
  my @message = split ( /^/m, $message );
  shift @message if ( $message[0] =~ /^From\s/ );    # trim mbox seperator
  my $msg = Mail::SpamAssassin::MIME->new();

  local $_;                                          # protect from abuse

  my $header = '';

  while ( my $last = shift @message ) {
    $last =~ s/\r\n/\n/;
    chomp($last);

    last if ( $last =~ /^$/m );

    # NB: Really need to figure out special folding rules here!
    if ( $last =~ s/^[ \t]+// ) {                    # if its a continuation
      $header .= " $last";                           # fold continuations
      next;
    }

    # not a continuation...
    if ($header) {
      my ( $key, $value ) = split ( /:\s*/, $header, 2 );
      if ( $key =~ /^content-type(?:-encoding)?$/i ) {
        $msg->header( $key, $class->decode_header($value), $value );
      }
    }

    $header = $last;
  }

  # Parse out the body ...
  my ($boundary) =
    $msg->header('content-type') =~ /boundary\s*=\s*["']?([^"';]+)["']?/i;
  $class->parse_body( $msg, $msg, $boundary, \@message );

  return $msg;
}

sub parse_body {
  my $class = shift;
  my ( $msg, $_msg, $boundary, $body ) = @_;

  for ( @{$body} ) {
    s/\r\n/\n/;
  }

  my $type = $_msg->header('Content-Type') || 'text/plain';

  #    warn "Parsing message of type: $type\n";

  if ( $type =~ /^text\/plain/i ) {
    debug("Parse text/plain\n");
    $class->parse_normal( $msg, $_msg, $boundary, $body );
  }
  elsif ( $type =~ /^text\/html/i ) {
    debug("Parse text/html\n");
    $class->parse_normal( $msg, $_msg, $boundary, $body );
  }
  elsif ( $type =~ /^multipart\/alternative/i ) {
    debug("Parse multipart/alternative\n");
    $class->parse_multipart_alternate( $msg, $_msg, $boundary, $body );
  }
  elsif ( $type =~ /^multipart\//i ) {
    debug("Parse $type\n");
    $class->parse_multipart_mixed( $msg, $_msg, $boundary, $body );
  }
  else {
    debug("Regular attachment\n");
    $class->decode_attachment( $msg, $_msg, $boundary, $body );
  }

  if ( !$msg->body() ) {
    debug("No message body found. Reparsing\n");
    my $part_fh  = [];
    my $part_msg = Mail::SpamAssassin::MIME->new();
    $class->decode_body( $msg, $part_msg, $boundary, $part_fh );
  }
}

sub parse_multipart_alternate {
  my $class = shift;
  my ( $msg, $_msg, $boundary, $body ) = @_;

  my $preamble = '';

  debug("m/a got boundary: $boundary\n");

  # extract preamble (normally contains "This message is in Multipart/MIME format")
  while ( my $line = shift @{$body} ) {
    last if $line =~ /^\-\-\Q$boundary\E$/;
    $preamble .= $line;
  }

  debug("preamble: [[$preamble]]\n");

  my $in_body = 0;

  my $header;
  my $part_fh;
  my $part_msg = Mail::SpamAssassin::MIME->new();

  my $line_count = @{$body};
  foreach ( @{$body} ) {

    # debug($_);
    if ( --$line_count == 0 || /^\-\-\Q$boundary\E/ ) {
      debug("m/a got end of section\n");

      # end of part
      my $line = $_;

      # per rfc 1521, the CRLF before the boundary is part of the boundary ...
      if ($part_fh) {
        chomp( $part_fh->[ scalar @{$part_fh} - 1 ] );
        splice @{$part_fh}, -1
          if ( $part_fh->[ scalar @{$part_fh} - 1 ] eq '' );
      }

      # assume body part if it's text
      if ( $part_msg->header('content-type') =~ /^text/i ) {
        $class->decode_body( $msg, $part_msg, $boundary, $part_fh );
      }
      else {
        debug("Likely virus?\n");
        $class->decode_attachment( $msg, $part_msg, $boundary, $part_fh );
      }
      last if $line =~ /^\-\-\Q$boundary\E\-\-$/;
      $in_body  = 0;
      $part_msg = Mail::SpamAssassin::MIME->new();
      undef $part_fh;
      next;
    }

    if ($in_body) {
      push ( @{$part_fh}, $_ );
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
  my $class = shift;
  my ( $msg, $_msg, $boundary, $body ) = @_;

  debug("m/m Got boundary: $boundary\n");
  my $preamble = '';

  # extract preamble (normally contains "This message is in Multipart/MIME format")
  while ( my $line = shift @{$body} ) {
    last if $line =~ /^\-\-\Q$boundary\E$/;
    $preamble .= $line;
  }

  debug("Extracted preamble: [[$preamble]]\n");

  my $part_msg =
    Mail::SpamAssassin::MIME->new();    # just used for headers storage
  my $in_body = 0;

  my $header;
  my $part_fh;

  my $line_count = @{$body};
  foreach ( @{$body} ) {
    if ( --$line_count == 0 || /^\-\-\Q$boundary\E/ ) {

      # end of part
      debug("Got end of MIME section: $_\n");
      my $line = $_;

      # per rfc 1521, the CRLF before the boundary is part of the boundary ...
      if ($part_fh) {
        chomp( $part_fh->[ scalar @{$part_fh} - 1 ] );
        splice @{$part_fh}, -1
          if ( $part_fh->[ scalar @{$part_fh} - 1 ] eq '' );
      }

      my ($p_boundary) =
        $part_msg->header('content-type') =~
        /boundary\s*=\s*["']?([^"';]+)["']?/i;
      $p_boundary ||= $boundary;
      $class->parse_body( $msg, $part_msg, $p_boundary, $part_fh );

      last if $line =~ /^\-\-\Q${boundary}\E\-\-$/;
      $in_body  = 0;
      $part_msg = Mail::SpamAssassin::MIME->new();
      undef $part_fh;
      next;
    }

    if ($in_body) {
      push ( @{$part_fh}, $_ );
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
  my $class = shift;
  my ( $msg, $_msg, $boundary, $body ) = @_;

  # extract body, store it in $msg
  $class->decode_body( $msg, $_msg, $boundary, $body );
}

use File::Path qw(rmtree);

sub _decode_header {
  my ( $encoding, $cte, $data ) = @_;

  if ( $cte eq 'B' ) {

    # base 64 encoded
    return MIME::Base64::decode_base64($data);
  }
  elsif ( $cte eq 'Q' ) {

    # quoted printable
    return MIME::QuotedPrint::decode_qp($data);
  }
  else {
    die "Unknown encoding type '$cte' in RFC2047 header";
  }
}

# decode according to RFC2047
sub decode_header {
  my $class = shift;
  my ($header) = @_;

  return '' unless $header;
  return $header unless $header =~ /=\?/;

  $header =~
    s/=\?([\w_-]+)\?([bqBQ])\?(.*?)\?=/_decode_header($1, uc($2), $3)/ge;
  return $header;
}

sub decode_body {
  my $class = shift;
  my ( $msg, $part_msg, $boundary, $body ) = @_;

  my ( $type, $content ) = $class->decode( $part_msg, $body );

  debug("got body: $type\n");

  $msg->add_body_part( $type, $content, $body, $boundary );
}

sub decode_attachment {
  my $class = shift;
  my ( $msg, $part_msg, $boundary, $fh ) = @_;

  debug("decoding attachment\n");

  my ( $type, $content, $filename ) = $class->decode( $part_msg, $fh );

  $msg->add_attachment( $type, $content, $filename, $boundary );
}

sub decode {
  my $class = shift;
  my ( $msg, $body ) = @_;

  # tvd - 2003/09/24 - The original code used Text::Iconv to deal with UTF-8 stuff and the like.
  # I haven't quite decided if we need to deal with the content-type stuff or not, so ...
  # 
  #    my $converter = NullConverter->new();
  #    if ($msg->header('content-type') && ($msg->header('content-type') =~ /^text\//i)) {
  #        # text type - might need to translate to UTF8
  #        my $type = $msg->header('content-type');
  #        # remember to strip charset portion - we can always add it later.
  #        if ($type =~ s/charset="?([^\";]+)"?;?//i) {
  #            my $charset = $1;
  #            $charset =~ s/us-ascii/ISO-8859-15/i; # some mailers are broken this way.
  #            $converter = $class->converter($charset);
  #            $msg->header('content-type', $type);
  #        }
  #    }

  if ( lc( $msg->header('content-transfer-encoding') ) eq 'quoted-printable' ) {
    debug("decoding QP file\n");
    my @output =
      split ( /^/m, MIME::Base64::decode_qp( join ( "", @{$body} ) ) );

    my $type = $msg->header('content-type');
    my ($filename) =
      ( $msg->header('content-disposition') =~ /name="?([^\";]+)"?/i );
    if ( !$filename ) {
      ($filename) = ( $msg->header('content-type') =~ /name="?([^\";]+)"?/i );
    }

    return $type, \@output, $filename;
  }
  elsif ( lc( $msg->header('content-transfer-encoding') ) eq 'base64' ) {
    debug("decoding B64 file\n");
    my @output =
      split ( /^/m, MIME::Base64::decode_base64( join ( "", @{$body} ) ) );

    my $type = $msg->header('content-type');
    my ($filename) =
      ( $msg->header('content-disposition') =~ /name="?([^\";]+)"?/i );
    if ( !$filename ) {
      ($filename) = ( $msg->header('content-type') =~ /name="?([^\";]+)"?/i );
    }

    return $type, \@output, $filename;
  }
  else {
    debug("decoding other encoding\n");

    # Encoding is one of 7bit, 8bit, binary or x-something - just save.
    my @output = @{$body};

    my $type = $msg->header('content-type');
    my ($filename) =
      ( $msg->header('content-disposition') =~ /name="?([^\";]+)"?/i );
    if ( !$filename ) {
      ($filename) = ( $msg->header('content-type') =~ /name="?([^\";]+)"?/i );
    }

    return $type, \@output, $filename;
  }
}

1;
__END__
