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
use Mail::SpamAssassin::PerMsgStatus; # HTML
use Mail::SpamAssassin::HTML;
use MIME::Base64;
use MIME::QuotedPrint;

=item parse()

Unlike most modules, Mail::SpamAssassin::MIME::Parser will not return an
object of the same type, but rather a Mail::SpamAssassin::MIME object.
To use it, simply call C<Mail::SpamAssassin::MIME::Parser->parse($msg)>,
where $msg is a scalar with the entire contents of the mesage.

More information should go here. ;)

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
        $msg->header( $key, $self->_decode_header($value), $value );
      }
    }

    # not a continuation...
    $header = $last;

    last if ( $last =~ /^$/m );
  }

  # Parse out the body ...
  # the actual ABNF, BTW:
  # boundary := 0*69<bchars> bcharsnospace
  # bchars := bcharsnospace / " "
  # bcharsnospace :=    DIGIT / ALPHA / "'" / "(" / ")" / "+" /"_"
  #               / "," / "-" / "." / "/" / ":" / "=" / "?"
  #
  my ($boundary) =
    $msg->header('content-type') =~ /boundary\s*=\s*["']?([^"';]+)["']?/i;
  $self->_parse_body( $msg, $msg, $boundary, \@message );

  return $msg;
}

sub _parse_body {
  my($self, $msg, $_msg, $boundary, $body) = @_;

  # CRLF -> LF
  for ( @{$body} ) {
    s/\r\n/\n/;
  }

  my $type = $_msg->header('Content-Type') || 'text/plain; charset=us-ascii';

  #    warn "Parsing message of type: $type\n";

  if ( $type =~ /^text\/plain/i ) {
    dbg("Parse text/plain\n");
    $self->_parse_normal( $msg, $_msg, $boundary, $body );
  }
  elsif ( $type =~ /^text\/html/i ) {
    dbg("Parse text/html\n");
    $self->_parse_normal( $msg, $_msg, $boundary, $body );
  }
  elsif ( $type =~ /^multipart\/alternative/i ) {
    dbg("Parse multipart/alternative\n");
    $self->_parse_multipart_alternate( $msg, $_msg, $boundary, $body );
  }
  elsif ( $type =~ /^multipart\//i ) {
    dbg("Parse $type\n");
    $self->_parse_multipart_mixed( $msg, $_msg, $boundary, $body );
  }
  else {
    dbg("Regular attachment\n");
    $self->_decode_body( $msg, $_msg, $boundary, $body );
  }

  if ( !$msg->body() ) {
    dbg("No message body found. Reparsing as blank.\n");
    my $part_msg = Mail::SpamAssassin::MIME->new();
    $self->_decode_body( $msg, $part_msg, $boundary, [] );
  }
}

sub _parse_multipart_alternate {
  my($self, $msg, $_msg, $boundary, $body ) = @_;

  $boundary ||= '';
  dbg("m/a got boundary: $boundary\n");

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

  my $in_body = 0;

  my $header;
  my $part_array;
  my $part_msg = Mail::SpamAssassin::MIME->new();

  my $line_count = @{$body};
  foreach ( @{$body} ) {
    if ( --$line_count == 0 || ($boundary && /^\-\-\Q$boundary\E/) ) {
      dbg("m/a got end of section\n");

      # end of part
      my $line = $_;

      # per rfc 1521, the CRLF before the boundary is part of the boundary ...
      # NOTE: The CRLF preceding the encapsulation line is conceptually
      # attached to the boundary so that it is possible to have a part
      # that does not end with a CRLF (line break). Body parts that must
      # be considered to end with line breaks, therefore, must have two
      # CRLFs preceding the encapsulation line, the first of which is part
      # of the preceding body part, and the second of which is part of the
      # encapsulation boundary.
      if ($part_array) {
        chomp( $part_array->[ scalar @{$part_array} - 1 ] );
        splice @{$part_array}, -1
          if ( $part_array->[ scalar @{$part_array} - 1 ] eq '' );

        $self->_decode_body( $msg, $part_msg, $boundary, $part_array );
      }

      last if ($boundary && $line =~ /^\-\-\Q$boundary\E\-\-$/);
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

sub _parse_multipart_mixed {
  my($self, $msg, $_msg, $boundary, $body) = @_;

  $boundary ||= '';
  dbg("m/m got boundary: $boundary\n");

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

  my $part_msg =
    Mail::SpamAssassin::MIME->new();    # just used for headers storage
  my $in_body = 0;

  my $header;
  my $part_array;

  my $line_count = @{$body};
  foreach ( @{$body} ) {
    if ( --$line_count == 0 || ($boundary && /^\-\-\Q$boundary\E/) ) {

      # end of part
      dbg("Got end of MIME section: $_\n");
      my $line = $_;

      # per rfc 1521, the CRLF before the boundary is part of the boundary ...
      # NOTE: The CRLF preceding the encapsulation line is conceptually
      # attached to the boundary so that it is possible to have a part
      # that does not end with a CRLF (line break). Body parts that must
      # be considered to end with line breaks, therefore, must have two
      # CRLFs preceding the encapsulation line, the first of which is part
      # of the preceding body part, and the second of which is part of the
      # encapsulation boundary.
      if ($part_array) {
        chomp( $part_array->[ scalar @{$part_array} - 1 ] );
        splice @{$part_array}, -1
          if ( $part_array->[ scalar @{$part_array} - 1 ] eq '' );

        my ($p_boundary) =
          $part_msg->header('content-type') =~
          /boundary\s*=\s*["']?([^"';]+)["']?/i;
        $p_boundary ||= $boundary;
        $self->_parse_body( $msg, $part_msg, $p_boundary, $part_array );
      }

      last if ($boundary && $line =~ /^\-\-\Q${boundary}\E\-\-$/);
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

sub _parse_normal {
  my($self, $msg, $_msg, $boundary, $body) = @_;

  # extract body, store it in $msg
  $self->_decode_body( $msg, $_msg, $boundary, $body );
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

# decode according to RFC2047
sub _decode_header {
  my($self, $header) = @_;

  return '' unless $header;
  return $header unless $header =~ /=\?/;

  $header =~
    s/=\?([\w_-]+)\?([bqBQ])\?(.*?)\?=/__decode_header($1, uc($2), $3)/ge;
  return $header;
}

sub _decode_body {
  my ($self, $msg, $part_msg, $boundary, $body) = @_;

  dbg("decoding attachment\n");

  my ($type, $decoded, $name) = $self->_decode($part_msg, $body);

  my $opts = {
  	decoded => $decoded,
	raw => $body,
	boundary => $boundary,
	headers => $part_msg->{headers},
	raw_headers => $part_msg->{raw_headers},
  };
  $opts->{name} = $name if $name;
  $opts->{rendered} = _render_text($decoded) if $type =~ m/^text/i;

  $msg->add_body_part( $type, $opts );
}

sub _decode {
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

# render text/plain as text/html based on a heuristic which simulates
# a certain common mail client
sub html_near_start {
  my ($pad) = @_;

  my $count = 0;
  $count += ($pad =~ tr/\n//d) * 2;
  $count += ($pad =~ tr/\n//cd);
  return ($count < 24);
}

sub _render_text {
  my ($decoded) = @_;

  my $text = join('', @{ $decoded });

  # render text/plain as text/html based on a heuristic which simulates
  # a certain common mail client
  if ($text =~ m/^(.{0,18}<(?:$Mail::SpamAssassin::PerMsgStatus::re_start)(?:\s.*?)?>)/ois &&
      html_near_start($1))
  {
    $text = "rendered as text/html";
  }
  else {
    $text = "rendered as text/plain";
  }
  return $text;
}

sub dbg { Mail::SpamAssassin::dbg (@_); }

1;
__END__

=back

=head1 SEE ALSO

C<Mail::SpamAssassin>
C<spamassassin>

