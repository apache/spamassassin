# $Id: MIME.pm,v 1.8 2003/10/02 22:59:00 quinlan Exp $

# @LICENSE

package Mail::SpamAssassin::MIME;
use strict;
use MIME::Base64;
use Mail::SpamAssassin;

sub new {
  my $class = shift;
  $class = ref($class) || $class;

  my $self = {
    headers     => {},
    raw_headers => {},
    body_parts  => [],
    };

  bless($self,$class);

  $self;
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

  # Trim whitespace off of the header keys
  $key       =~ s/^\s+//;
  $key       =~ s/\s+$//;

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
  my($self, $raw_type, $opts) = @_;

  my $type = $raw_type;
  $type     ||= 'text/plain';
  $type =~ s/;.*$//;            # strip everything after first semi-colon
  $type =~ s/[^a-zA-Z\/]//g;    # strip inappropriate chars

  my $part = {
    type     => $type,
  };

  while( my($k,$v) = each %{$opts} ) {
    $part->{$k} = $v;
  }

  # Add the part to body_parts
  push @{ $self->{body_parts} }, $part;
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

sub dbg { Mail::SpamAssassin::dbg (@_); }

1;
__END__
