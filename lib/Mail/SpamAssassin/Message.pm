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

Mail::SpamAssassin::Message - decode, render, and hold an RFC-2822 message

=head1 SYNOPSIS

=head1 DESCRIPTION

This module will encapsulate an email message and allow access to
the various MIME message parts and message metadata.

=head1 PUBLIC METHODS

=over 4

=cut

# the message structure is now:
#
# Message object, also top-level node in MsgNode tree
#    |
#    +---> MsgNode for other parts in MIME structure
#    |       |---> [ more MsgNode parts ... ]
#    |       [ others ... ]
#    |
#    +---> MsgMetadata object to hold metadata

package Mail::SpamAssassin::Message;
use strict;
use Mail::SpamAssassin;
use Mail::SpamAssassin::MsgNode;
use Mail::SpamAssassin::MsgMetadata;

use vars qw(@ISA);

@ISA = qw(Mail::SpamAssassin::MsgNode);

# ---------------------------------------------------------------------------

=item new()

=cut

sub new {
  my $class = shift;
  $class = ref($class) || $class;
  my %opts = @_;
  my $self = $class->SUPER::new(%opts);

  $self->{pristine_headers} =	'';
  $self->{pristine_body} =	'';
  $self->{already_parsed} =	1;

  # allow callers to set certain options ...
  foreach ( 'already_parsed' ) {
    $self->{$_} = $opts{$_} if ( exists $opts{$_} );
  }

  bless($self,$class);

  # create the metadata holder class
  $self->{metadata} = Mail::SpamAssassin::MsgMetadata->new($self);

  $self;
}

# ---------------------------------------------------------------------------

=item _do_parse()

Non-Public function which will initiate a MIME part parse (generates
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
}

=item find_parts()

=cut

# Used to find any MIME parts whose simple content-type matches a given regexp
# Searches it's own and any children parts.  Returns an array of MIME
# objects which match.
#
sub find_parts {
  my ($self, $re, $onlyleaves, $recursive) = @_;

  # ok, we need to do the parsing now...
  $self->_do_parse() if (!$self->{'already_parsed'});

  # and pass through to the MsgNode version of the method
  return $self->SUPER::find_parts($re, $onlyleaves, $recursive);
}

# ---------------------------------------------------------------------------

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
  if (!$self->{metadata}) {
    warn "oops! get_metadata() called after finish_metadata()"; return;
  }
  $self->{metadata}->{strings}->{$hdr};
}

=item put_metadata($hdr, $text)

=cut

sub put_metadata {
  my ($self, $hdr, $text) = @_;
  if (!$self->{metadata}) {
    warn "oops! put_metadata() called after finish_metadata()"; return;
  }
  $self->{metadata}->{strings}->{$hdr} = $text;
}

=item delete_metadata($hdr)

=cut

sub delete_metadata {
  my ($self, $hdr) = @_;
  if (!$self->{metadata}) {
    warn "oops! delete_metadata() called after finish_metadata()"; return;
  }
  delete $self->{metadata}->{strings}->{$hdr};
}

=item $str = get_all_metadata()

=cut

sub get_all_metadata {
  my ($self) = @_;

  if (!$self->{metadata}) {
    warn "oops! get_all_metadata() called after finish_metadata()"; return;
  }
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
  if (defined ($self->{metadata})) {
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
