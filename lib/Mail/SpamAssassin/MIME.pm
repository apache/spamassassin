# $Id: MIME.pm,v 1.2 2003/09/24 19:30:32 felicity Exp $

package Mail::SpamAssassin::MIME;
use strict;
use MIME::Base64 qw(encode_base64);

sub new {
  bless {
    headers     => {},
    raw_headers => {},

    body_parts  => [],
    attachments => [],
    },
    shift;
}

sub header {
  my $self   = shift;
  my $rawkey = shift;
  my $key    = lc($rawkey);

  # Trim whitespace off of the header keys
  $key       =~ s/^\s+//;
  $key       =~ s/\s+$//;

  if (@_) {
    my ( $decoded_value, $raw_value ) = @_;
    $raw_value = $decoded_value unless defined $raw_value;
    if ( exists $self->{headers}{$key} ) {
      push @{ $self->{headers}{$key} },     $decoded_value;
      push @{ $self->{raw_headers}{$key} }, $raw_value;
    }
    else {
      $self->{headers}{$key}     = [$decoded_value];
      $self->{raw_headers}{$key} = [$raw_value];
    }
    return $self->{headers}{$key}[-1];
  }

  my $want = wantarray;
  if ( defined($want) ) {
    if ($want) {
      return unless exists $self->{headers}{$key};
      return @{ $self->{headers}{$key} };
    }
    else {
      return '' unless exists $self->{headers}{$key};
      return $self->{headers}{$key}[-1];
    }
  }
}

sub raw_header {
  my $self = shift;
  my $key  = lc(shift);

  if (wantarray) {
    return unless exists $self->{raw_headers}{$key};
    return @{ $self->{raw_headers}{$key} };
  }
  else {
    return '' unless exists $self->{raw_headers}{$key};
    return $self->{raw_headers}{$key}[-1];
  }
}

sub add_body_part {
  my $self = shift;
  my ( $type, $decoded, $raw, $boundary ) = @_;
  $boundary ||= '';
  $type     ||= 'text/plain';
  $type =~ s/;.*$//;            # strip everything after first semi-colon
  $type =~ s/[^a-zA-Z\/]//g;    # strip inappropriate chars
  my $part =
    {
    type     => $type,
    decoded  => $decoded,
    raw      => $raw,
    boundary => $boundary,
    };
  $part->{parsed} = [] if ( $type eq "text/html" );
  push @{ $self->{body_parts} }, $part;
}

sub add_attachment {
  my $self = shift;
  my ( $type, $lines, $name, $raw, $boundary ) = @_;
  push @{ $self->{attachments} },
    {
    filename => $name,
    type     => $type,
    decoded  => $lines,
    raw      => $raw,
    boundary => $boundary,
    };
}

sub body {
  my $self = shift;
  my $type = lc(shift);
  return unless @{ $self->{body_parts} };
  if ($type) {

    # warn("body has ", scalar(@{ $self->{body_parts} }), " [$type]\n");
    foreach my $body ( @{ $self->{body_parts} } ) {

      # warn("type: $body->[0]\n");
      if ( $type eq lc( $body->{type} ) ) {
        return $body;
      }
    }
  }
  else {

    # return first body part
    return $self->{body_parts}[0];
  }
}

sub bodies {
  my $self = shift;
  return @{ $self->{body_parts} };
}

sub attachment {
  my $self = shift;
  return $self->{attachments}[shift];
}

sub attachments {
  my $self = shift;
  return @{ $self->{attachments} };
}

sub num_attachments {
  my $self = shift;
  return scalar @{ $self->{attachments} };
}

1;
__END__
