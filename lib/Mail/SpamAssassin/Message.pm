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

Mail::SpamAssassin::Message - decode, render, and hold an RFC-2822 message

=head1 DESCRIPTION

This module encapsulates an email message and allows access to the various MIME
message parts and message metadata.

The message structure, after initiating a parse() cycle, looks like this:

  Message object, also top-level node in Message::Node tree
     |
     +---> Message::Node for other parts in MIME structure
     |       |---> [ more Message::Node parts ... ]
     |       [ others ... ]
     |
     +---> Message::Metadata object to hold metadata

=head1 PUBLIC METHODS

=over 4

=cut

package Mail::SpamAssassin::Message;

use strict;
use warnings;
use re 'taint';

BEGIN {
  eval { require Digest::SHA; import Digest::SHA qw(sha1 sha1_hex); 1 }
  or do { require Digest::SHA1; import Digest::SHA1 qw(sha1 sha1_hex) }
}

use Mail::SpamAssassin;
use Mail::SpamAssassin::Message::Node;
use Mail::SpamAssassin::Message::Metadata;
use Mail::SpamAssassin::Constants qw(:sa);
use Mail::SpamAssassin::Logger;

use vars qw(@ISA);

@ISA = qw(Mail::SpamAssassin::Message::Node);

# ---------------------------------------------------------------------------

=item new()

Creates a Mail::SpamAssassin::Message object.  Takes a hash reference
as a parameter.  The used hash key/value pairs are as follows:

C<message> is either undef (which will use STDIN), a scalar - a string
containing an entire message, a reference to such string, an array reference
of the message with one line per array element, or either a file glob
or an IO::File object which holds the entire contents of the message.

Note: The message is expected to generally be in RFC 2822 format, optionally
including an mbox message separator line (the "From " line) as the first line.

C<parse_now> specifies whether or not to create the MIME tree
at object-creation time or later as necessary.

The I<parse_now> option, by default, is set to false (0).
This allows SpamAssassin to not have to generate the tree of
Mail::SpamAssassin::Message::Node objects and their related data if the
tree is not going to be used.  This is handy, for instance, when running
C<spamassassin -d>, which only needs the pristine header and body which
is always handled when the object is created.

C<subparse> specifies how many MIME recursion levels should be parsed.
Defaults to 20.

=cut

# month mappings (ripped from Util.pm)
my %MONTH = (jan => 1, feb => 2, mar => 3, apr => 4, may => 5, jun => 6,
	     jul => 7, aug => 8, sep => 9, oct => 10, nov => 11, dec => 12);

# day of week mapping (starting from zero)
my @DAY_OF_WEEK = qw/Sun Mon Tue Wed Thu Fri Sat/ ;

sub new {
  my $class = shift;
  $class = ref($class) || $class;

  my($opts) = @_;
  my $message = defined $opts->{'message'} ? $opts->{'message'} : \*STDIN;
  my $parsenow = $opts->{'parsenow'} || 0;
  my $normalize = $opts->{'normalize'} || 0;

  # Specifies whether or not to parse message/rfc822 parts into its own tree.
  # If the # > 0, it'll subparse, otherwise it won't.  By default, do twenty
  # levels deep.
  my $subparse = defined $opts->{'subparse'} ? $opts->{'subparse'} : 20;

  my $self = $class->SUPER::new({normalize=>$normalize});

  $self->{tmpfiles} =           [];
  $self->{pristine_headers} =	'';
  $self->{pristine_body} =	'';
  $self->{mime_boundary_state} = {};
  $self->{line_ending} =	"\012";
  $self->{master_deadline} = $opts->{'master_deadline'};
  $self->{suppl_attrib} = $opts->{'suppl_attrib'};

  if ($self->{suppl_attrib}) {  # caller-provided additional information
    # pristine_body_length is currently used by an eval test check_body_length
    # Possible To-Do: Base the length on the @message array later down?
    if (defined $self->{suppl_attrib}{body_size}) {
      # Optional info provided by a caller; should reflect the original
      # message body size if provided, and as such it may differ from the
      # $self->{pristine_body} size, e.g. when the caller passed a truncated
      # message to SpamAssassin, or when counting line-endings differently.
      $self->{pristine_body_length} = $self->{suppl_attrib}{body_size};
    }
    if (ref $self->{suppl_attrib}{mimepart_digests}) {
      # Optional info provided by a caller: an array of digest codes (e.g. SHA1)
      # of each MIME part. Should reflect the original message if provided.
      # As such it may differ from digests calculated by get_mimepart_digests(),
      # e.g. when the caller passed a truncated message to SpamAssassin.
      $self->{mimepart_digests} = $self->{suppl_attrib}{mimepart_digests};
    }
  }

  bless($self,$class);

  # create the metadata holder class
  $self->{metadata} = Mail::SpamAssassin::Message::Metadata->new($self);

  # Ok, go ahead and do the message "parsing"

  # protect it from abuse ...
  local $_;

  # Figure out how the message was passed to us, and deal with it.
  my @message;
  if (ref $message eq 'ARRAY') {
     @message = @{$message};
  }
  elsif (ref($message) eq 'GLOB' || ref($message) =~ /^IO::/) {
    if (defined fileno $message) {

      # sysread+split avoids a Perl I/O bug (Bug 5985)
      # and is faster than (<$message>) by 10..25 %
      # (a drawback is a short-term double storage of a text in $raw_str)
      #
      my($nread,$raw_str); $raw_str = '';
      while ( $nread=sysread($message, $raw_str, 16384, length $raw_str) ) { }
      defined $nread  or die "error reading: $!";
      @message = split(/^/m, $raw_str, -1);

      if ($raw_str eq '') {
        dbg("message: empty message read");
      } elsif (length($raw_str) > 128*1024) {
        # ditch rarely used large chunks of allocated memory, Bug 6514
        #   http://www.perlmonks.org/?node_id=803515
        # about 97% of mail messages are below 128 kB,
        # about 98% of mail messages are below 256 kB (2010 statistics)
        # dbg("message: deallocating %.2f MB", length($raw_str)/1024/1024);
        undef $raw_str;
      }
    }
  }
  elsif (ref $message eq 'SCALAR') {
    @message = split(/^/m, $$message, -1);
  }
  elsif (ref $message) {
    dbg("message: Input is a reference of unknown type!");
  }
  elsif (defined $message) {
    @message = split(/^/m, $message, -1);
  }

  # Pull off mbox and mbx separators
  # also deal with null messages
  if (!@message) {
    # bug 4884:
    # if we get here, it means that the input was null, so fake the message
    # content as a single newline...
    @message = ("\n");
  } elsif ($message[0] =~ /^From\s+(?!:)/) {
    # careful not to confuse with obsolete syntax which allowed WSP before ':'
    # mbox formated mailbox
    $self->{'mbox_sep'} = shift @message;
  } elsif ($message[0] =~ MBX_SEPARATOR) {
    $_ = shift @message;

    # Munge the mbx message separator into mbox format as a sort of
    # de facto portability standard in SA's internals.  We need to
    # to this so that Mail::SpamAssassin::Util::parse_rfc822_date
    # can parse the date string...
    if (/([\s\d]\d)-([a-zA-Z]{3})-(\d{4})\s(\d{2}):(\d{2}):(\d{2})/) {
      # $1 = day of month
      # $2 = month (text)
      # $3 = year
      # $4 = hour
      # $5 = min
      # $6 = sec
      my @arr = localtime(timelocal($6,$5,$4,$1,$MONTH{lc($2)}-1,$3));
      my $address;
      foreach (@message) {
  	if (/^From:[^<]*<([^>]+)>/) {
  	    $address = $1;
  	    last;
  	} elsif (/^From:\s*([^<> ]+)/) {
  	    $address = $1;
  	    last;
  	}
      }
      $self->{'mbox_sep'} = "From $address $DAY_OF_WEEK[$arr[6]] $2 $1 $4:$5:$6 $3\n";
    }
  }

  # bug 4363
  # Check to see if we should do CRLF instead of just LF
  # For now, just check the first and last line and do whatever it does
  if (@message && ($message[0] =~ /\015\012/ || $message[-1] =~ /\015\012/)) {
    $self->{line_ending} = "\015\012";
    dbg("message: line ending changed to CRLF");
  }

  # Is a CRLF -> LF line endings conversion necessary?
  my $squash_crlf = $self->{line_ending} eq "\015\012";

  # Go through all the header fields of the message
  my $hdr_errors = 0;
  my $header;
  for (;;) {
    # make sure not to lose the last header field when there is no body
    my $eof = !@message;
    my $current = $eof ? "\n" : shift @message;

    if ( $current =~ /^[ \t]/ ) {
      # This wasn't useful in terms of a rule, but we may want to treat it
      # specially at some point.  Perhaps ignore it?
      #unless ($current =~ /\S/) {
      #  $self->{'obsolete_folding_whitespace'} = 1;
      #}

      $header = ''  if !defined $header;  # header starts with a continuation!?
      $header .= $current;  # append continuations, no matter what
      $self->{'pristine_headers'} .= $current;
    }
    else {  # not a continuation
      # Ok, there's a header here, let's go ahead and add it in.
      if (defined $header) {  # deal with a previous header field
        my ($key, $value) = split (/:/s, $header, 2);

        # If it's not a valid header (aka: not in the form "foo:bar"), skip it.
        if (defined $value) {
	  # CRLF -> LF line-endings conversion if necessary
	  $value =~ s/\015\012/\012/sg  if $squash_crlf;
	  $key =~ s/[ \t]+\z//;  # strip WSP before colon, obsolete rfc822 syn
	  # limit the length of the pairs we store
	  if (length($key) > MAX_HEADER_KEY_LENGTH) {
	    $key = substr($key, 0, MAX_HEADER_KEY_LENGTH);
	    $self->{'truncated_header'} = 1;
	  }
	  if (length($value) > MAX_HEADER_VALUE_LENGTH) {
	    $value = substr($value, 0, MAX_HEADER_VALUE_LENGTH);
	    $self->{'truncated_header'} = 1;
	  }
          $self->header($key, $value);
        }
      }

      if ($current =~ /^\r?$/) {  # a regular end of a header section
	if ($eof) {
	  $self->{'missing_head_body_separator'} = 1;
	} else {
	  $self->{'pristine_headers'} .= $current;
	}
	last;
      }
      elsif ($current =~ /^--/) {  # mime boundary encountered, bail out
	$self->{'missing_head_body_separator'} = 1;
	unshift(@message, $current);
 	last;
      }
      # should we assume entering a body on encountering invalid header field?
      else {
        # no re "strict";  # since perl 5.21.8: Ranges of ASCII printables...
        if ($current !~ /^[\041-\071\073-\176]+[ \t]*:/) {
	  # A field name MUST be composed of printable US-ASCII characters
	  # (i.e., characters that have values between 33 (041) and 126 (176),
	  # inclusive), except colon (072). Obsolete header field syntax
	  # allowed WSP before a colon.
	  if (++$hdr_errors <= 3) {
	    # just consume but ignore a few invalid header fields
	  } else {  # enough is enough...
	    $self->{'missing_head_body_separator'} = 1;
	    unshift(@message, $current);
 	    last;
	  }
	}
      }

      # start collecting a new header field
      $header = $current;
      $self->{'pristine_headers'} .= $current;
    }
  }
  undef $header;

  # Store the pristine body for later -- store as a copy since @message
  # will get modified below
  $self->{'pristine_body'} = join('', @message);

  if (!defined $self->{pristine_body_length}) {
    $self->{'pristine_body_length'} = length $self->{'pristine_body'};
  }

  # iterate over lines in reverse order
  # merge multiple blank lines into a single one
  my $start;
  for (my $cnt=$#message; $cnt>=0; $cnt--) {
    # CRLF -> LF line-endings conversion if necessary
    $message[$cnt] =~ s/\015\012\z/\012/  if $squash_crlf;

    # line is blank
    if ($message[$cnt] =~ /^\s*$/) {
      # /^\s*$/ is about 5% faster then !/\S/, but still expensive here
      if (!defined $start) {
        $start=$cnt;
      }
      next unless $cnt == 0;
    }

    # line is not blank, or we've reached the beginning

    # if we've got a series of blank lines, get rid of them
    if (defined $start) {
      my $max_blank_lines = 20;
      my $num = $start-$cnt;
      if ($num > $max_blank_lines) {
        splice @message, $cnt+2, $num-$max_blank_lines;
      }
      undef $start;
    }
  }

  # Figure out the boundary
  my ($boundary);
  ($self->{'type'}, $boundary) = Mail::SpamAssassin::Util::parse_content_type($self->header('content-type'));
  dbg("message: main message type: ".$self->{'type'});

#  dbg("message: \$message[0]: \"" . $message[0] . "\"");

  # bug 6845: if main message type is multipart and the message body does not begin with
  # either a blank line or the boundary (if defined), insert a blank line
  # to ensure proper parsing - do not consider MIME headers at the beginning of the body
  # to be part of the message headers.
  if ($self->{'type'} =~ /^multipart\//i && $#message > 0 && $message[0] =~ /\S/)
  {
    if (!defined $boundary || $message[0] !~ /^--\Q$boundary\E/)
    {
      dbg("message: Inserting blank line at top of body to ensure correct multipart MIME parsing");
      unshift(@message, "\012");
    }
  }

#  dbg("message: \$message[0]: \"" . $message[0] . "\"");
#  dbg("message: \$message[1]: \"" . $message[1] . "\"");

  # parse queue, simple array of parts to parse:
  # 0: part object, already in the tree
  # 1: boundary used to focus body parsing
  # 2: message content
  # 3: how many MIME subparts to parse down
  #
  $self->{'parse_queue'} = [ [ $self, $boundary, \@message, $subparse ] ];

  # If the message does need to get parsed, save off a copy of the body
  # in a format we can easily parse later so we don't have to rip from
  # pristine_body ...  If we do want to parse now, go ahead and do so ...
  #
  if ($parsenow) {
    $self->parse_body();
  }

  $self;
}

# ---------------------------------------------------------------------------

=item find_parts()

Used to search the tree for specific MIME parts.  See
I<Mail::SpamAssassin::Message::Node> for more details.

=cut

# Used to find any MIME parts whose simple content-type matches a given regexp
# Searches it's own and any children parts.  Returns an array of MIME
# objects which match.
#
sub find_parts {
  my $self = shift;

  # ok, we need to do the parsing now...
  $self->parse_body() if (exists $self->{'parse_queue'});

  # and pass through to the Message::Node version of the method
  return $self->SUPER::find_parts(@_);
}

# ---------------------------------------------------------------------------

=item get_pristine_header()

Returns pristine headers of the message.  If no specific header name
is given as a parameter (case-insensitive), then all headers will be
returned as a scalar, including the blank line at the end of the headers.

If called in an array context, an array will be returned with each
specific header in a different element.  In a scalar context, the last
specific header is returned.

ie: If 'Subject' is specified as the header, and there are 2 Subject
headers in a message, the last/bottom one in the message is returned in
scalar context or both are returned in array context.

Btw, returning the last header field (not the first) happens to be consistent
with DKIM signatures, which search for and cover multiple header fields
bottom-up according to the 'h' tag. Let's keep it this way.

Note: the returned header will include the ending newline and any embedded
whitespace folding.

=cut

sub get_pristine_header {
  my ($self, $hdr) = @_;
  
  return $self->{pristine_headers} if !defined $hdr || $hdr eq '';
  my(@ret) =
    $self->{pristine_headers} =~ /^\Q$hdr\E[ \t]*:[ \t]*(.*?\n(?![ \t]))/smgi;
  # taintedness is retained by "use re 'taint'" (fix in bug 5283 now redundant)
  if (!@ret) {
    return $self->get_header($hdr);
  } elsif (wantarray) {
    return @ret;
  } else {
    return $ret[-1];
  }
}

=item get_mbox_separator()

Returns the mbox separator found in the message, or undef if there
wasn't one.

=cut

sub get_mbox_separator {
  return $_[0]->{mbox_sep};
}

=item get_body()

Returns an array of the pristine message body, one line per array element.

=cut

sub get_body {
  my ($self) = @_;
  my @ret = split(/^/m, $self->{pristine_body});
  return \@ret;
}

# ---------------------------------------------------------------------------

=item get_pristine()

Returns a scalar of the entire pristine message.

=cut

sub get_pristine {
  my ($self) = @_;
  return $self->{pristine_headers} . $self->{pristine_body};
}

=item get_pristine_body()

Returns a scalar of the pristine message body.

=cut

sub get_pristine_body {
  my ($self) = @_;
  return $self->{pristine_body};
}

# ---------------------------------------------------------------------------

=item extract_message_metadata($permsgstatus)

=cut

sub extract_message_metadata {
  my ($self, $permsgstatus) = @_;

  # do this only once per message, it can be expensive
  return  if $self->{already_extracted_metadata};
  $self->{already_extracted_metadata} = 1;

  $self->{metadata}->extract ($self, $permsgstatus);
}

# ---------------------------------------------------------------------------

=item $str = get_metadata($hdr)

=cut

sub get_metadata {
  my ($self, $hdr) = @_;
  if (!$self->{metadata}) {
    warn "metadata: oops! get_metadata() called after finish_metadata()"; return;
  }
# dbg("message: get_metadata - %s: %s", $hdr, defined $_ ? $_ : '<undef>')
#   for $self->{metadata}->{strings}->{lc $hdr};

  $self->{metadata}->{strings}->{lc $hdr};
}

=item put_metadata($hdr, $text)

=cut

sub put_metadata {
  my ($self, $hdr, $text) = @_;
  if (!$self->{metadata}) {
    warn "metadata: oops! put_metadata() called after finish_metadata()"; return;
  }
# dbg("message: put_metadata - %s: %s", $hdr, $text);
  $self->{metadata}->{strings}->{lc $hdr} = $text;
}

=item delete_metadata($hdr)

=cut

sub delete_metadata {
  my ($self, $hdr) = @_;
  if (!$self->{metadata}) {
    warn "metadata: oops! delete_metadata() called after finish_metadata()"; return;
  }
  delete $self->{metadata}->{strings}->{lc $hdr};
}

=item $str = get_all_metadata()

=cut

sub get_all_metadata {
  my ($self) = @_;

  if (!$self->{metadata}) {
    warn "metadata: oops! get_all_metadata() called after finish_metadata()"; return;
  }
  my @ret;
  my $keys_ref = $self->{metadata}->{strings};
  foreach my $key (sort keys %$keys_ref) {
    my $val = $keys_ref->{$key};
    $val = ''  if !defined $val;
    push (@ret, "$key: $val\n");
  }
  return (wantarray ? @ret :  join('', @ret));
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

  # Clean ourself up
  $self->finish_metadata();

  # These will only be in the root Message node
  delete $self->{'mime_boundary_state'};
  delete $self->{'mbox_sep'};
  delete $self->{'normalize'};
  delete $self->{'pristine_body'};
  delete $self->{'pristine_headers'};
  delete $self->{'line_ending'};
  delete $self->{'missing_head_body_separator'};

  my @toclean = ( $self );

  # Go ahead and clean up all of the Message::Node parts
  while (my $part = shift @toclean) {
    # bug 5557: windows requires tmp file be closed before it can be rm'd
    if (ref $part->{'raw'} eq 'GLOB') {
      close($part->{'raw'})  or die "error closing input file: $!";
    }

    # bug 5858: avoid memory leak with deep MIME structure
    if (defined ($part->{metadata})) {
      $part->{metadata}->finish();
      delete $part->{metadata};
    }

    delete $part->{'headers'};
    delete $part->{'raw_headers'};
    delete $part->{'header_order'};
    delete $part->{'raw'};
    delete $part->{'decoded'};
    delete $part->{'rendered'};
    delete $part->{'visible_rendered'};
    delete $part->{'invisible_rendered'};
    delete $part->{'type'};
    delete $part->{'rendered_type'};

    # if there are children nodes, add them to the queue of nodes to clean up
    if (exists $part->{'body_parts'}) {
      push(@toclean, @{$part->{'body_parts'}});
      delete $part->{'body_parts'};
    }
  }

  # delete temporary files
  if ($self->{'tmpfiles'}) {
    for my $fn (@{$self->{'tmpfiles'}}) {
      unlink($fn) or warn "cannot unlink $fn: $!";
    }
    delete $self->{'tmpfiles'};
  }
}

# also use a DESTROY method, just to ensure (as much as possible) that
# temporary files are deleted even if the finish() method is omitted
sub DESTROY {
  my $self = shift;
  # best practices: prevent potential calls to eval and to system routines
  # in code of a DESTROY method from clobbering global variables $@ and $! 
  local($@,$!);  # keep outer error handling unaffected by DESTROY
  if ($self->{'tmpfiles'}) {
    for my $fn (@{$self->{'tmpfiles'}}) {
      unlink($fn) or dbg("message: cannot unlink $fn: $!");
    }
  }
}

# ---------------------------------------------------------------------------

=item receive_date()

Return a time_t value with the received date of the current message,
or current time if received time couldn't be determined.

=cut

sub receive_date {
  my($self) = @_;

  return Mail::SpamAssassin::Util::receive_date(scalar $self->get_all_headers(0,1));
}

# ---------------------------------------------------------------------------

=back

=head1 PARSING METHODS, NON-PUBLIC

These methods take a RFC2822-esque formatted message and create a tree
with all of the MIME body parts included.  Those parts will be decoded
as necessary, and text/html parts will be rendered into a standard text
format, suitable for use in SpamAssassin.

=over 4

=item parse_body()

parse_body() passes the body part that was passed in onto the
correct part parser, either _parse_multipart() for multipart/* parts,
or _parse_normal() for everything else.  Multipart sections become the
root of sub-trees, while everything else becomes a leaf in the tree.

For multipart messages, the first call to parse_body() doesn't create a
new sub-tree and just uses the parent node to contain children.  All other
calls to parse_body() will cause a new sub-tree root to be created and
children will exist underneath that root.  (this is just so the tree
doesn't have a root node which points at the actual root node ...)

=cut

sub parse_body {
  my($self) = @_;

  # This shouldn't happen, but just in case, abort.
  return unless (exists $self->{'parse_queue'});

  dbg("message: ---- MIME PARSER START ----");

  while (my $toparse = shift @{$self->{'parse_queue'}}) {
    # multipart sections are required to have a boundary set ...  If this
    # one doesn't, assume it's malformed and send it to be parsed as a
    # non-multipart section
    #
    my ($msg, $boundary, $body, $subparse) = @$toparse;

    if ($msg->{'type'} =~ m{^multipart/}i && defined $boundary && $subparse > 0) {
      $self->_parse_multipart($toparse);
    }
    else {
      # If it's not multipart, go ahead and just deal with it.
      $self->_parse_normal($toparse);

      # bug 5041: process message/*, but exclude message/partial content types
      if ($msg->{'type'} =~ m{^message/(?!partial\z)}i && $subparse > 0)
      {
        # Just decode the part, but we don't need the resulting string here.
        $msg->decode(0);

        # bug 7125: decode and parse only message/rfc822 or message/global,
        # but do not treat other message/* content types (like the ones listed
        # here) as a message consisting of a header and a body, as they are not:
        #    message/delivery-status, message/global-delivery-status,
        #    message/feedback-report, message/global-headers,
        #    message/global-disposition-notification,
        #    message/disposition-notification, (and message/partial)

        # bug 5051, bug 3748: check $msg->{decoded}: sometimes message/* parts
        # have no content, and we get stuck waiting for STDIN, which is bad. :(

        if ($msg->{'type'} =~ m{^message/(?:rfc822|global)\z}i &&
            defined $msg->{'decoded'} && $msg->{'decoded'} ne '')
        {
	  # Ok, so this part is still semi-recursive, since M::SA::Message
	  # calls M::SA::Message, but we don't subparse the new message,
	  # and pull a sneaky "steal our child's queue" maneuver to deal
	  # with it on our own time.  Reference the decoded array directly
	  # since it's faster.
	  # 
          my $msg_obj = Mail::SpamAssassin::Message->new({
    	    message	=>	$msg->{'decoded'},
	    parsenow	=>	0,
	    normalize	=>	$self->{normalize},
	    subparse	=>	$subparse - 1,
	    });

	  # Add the new message to the current node
          $msg->add_body_part($msg_obj);

	  # now this is the sneaky bit ... steal the sub-message's parse_queue
	  # and add it to ours.  then we'll handle the sub-message in our
	  # normal loop and get all the glory.  muhaha.  :)
	  push(@{$self->{'parse_queue'}}, @{$msg_obj->{'parse_queue'}});
	  delete $msg_obj->{'parse_queue'};

	  # Ok, we've subparsed, so go ahead and remove the raw and decoded
	  # data because we won't need them anymore (the tree under this part
	  # will have that data)
	  if (ref $msg->{'raw'} eq 'GLOB') {
	    # Make sure we close it if it's a temp file -- Bug 5166
	    close($msg->{'raw'})
	      or die "error closing input file: $!";
	  }

	  delete $msg->{'raw'};
	  
	  delete $msg->{'decoded'};
        }
      }
    }
  }

  dbg("message: ---- MIME PARSER END ----");

  # we're done parsing, so remove the queue variable
  delete $self->{'parse_queue'};
}

=item _parse_multipart()

Generate a root node, and for each child part call parse_body()
to generate the tree.

=cut

sub _parse_multipart {
  my($self, $toparse) = @_;

  my ($msg, $boundary, $body, $subparse) = @{$toparse};

  # we're not supposed to be a leaf, so prep ourselves
  $msg->{'body_parts'} = [];

  # the next set of objects will be one level deeper
  $subparse--;

  dbg("message: parsing multipart, got boundary: ".(defined $boundary ? $boundary : ''));

  # NOTE: The MIME boundary REs here are very specific to be mostly RFC 1521
  # compliant, but also allow possible malformations to still work.  Please
  # see Bugzilla bug 3749 for more information before making any changes!

  # ignore preamble per RFC 1521, unless there's no boundary ...
  if ( defined $boundary ) {
    my $line;
    my $tmp_line = @{$body};
    for ($line=0; $line < $tmp_line; $line++) {
#     dbg("message: multipart line $line: \"" . $body->[$line] . "\"");
      # specifically look for an opening boundary
      if (substr($body->[$line],0,2) eq '--'  # triage
          && $body->[$line] =~ /^--\Q$boundary\E\s*$/) {
	# Make note that we found the opening boundary
	$self->{mime_boundary_state}->{$boundary} = 1;

	# if the line after the opening boundary isn't a header, flag it.
	# we need to make sure that there's actually another line though.
	# no re "strict";  # since perl 5.21.8: Ranges of ASCII printables...
	if ($line+1 < $tmp_line && $body->[$line+1] !~ /^[\041-\071\073-\176]+:/) {
	  $self->{'missing_mime_headers'} = 1;
	}

        last;
      }
    }

    # Found a boundary, ignore the preamble
    if ( $line < $tmp_line ) {
      splice @{$body}, 0, $line+1;
    }

    # Else, there's no boundary, so leave the whole part...
  }

  # prepare a new tree node
  my $part_msg = Mail::SpamAssassin::Message::Node->new({ normalize=>$self->{normalize} });
  my $in_body = 0;
  my $header;
  my $part_array;
  my $found_end_boundary;

  my $line_count = @{$body};
  foreach ( @{$body} ) {
    # if we're on the last body line, or we find any boundary marker,
    # deal with the mime part;
    # a triage before an unlikely-to-match regexp avoids a CPU hotspot
    $found_end_boundary = defined $boundary && substr($_,0,2) eq '--'
                          && /^--\Q$boundary\E(?:--)?\s*$/;
    if ( --$line_count == 0 || $found_end_boundary ) {
      my $line = $_; # remember the last line

      # If at last line and no end boundary found, the line belongs to body
      # TODO:
      #  Is $self->{mime_boundary_state}->{$boundary}-- needed here?
      #  Could "missing end boundary" be a useful rule? Mark it somewhere?
      #  If SA processed truncated message from amavis etc, this could also
      #  be hit legimately..
      if (!$found_end_boundary) {
        # TODO: This is duplicate code from few pages down below..
        while (length ($_) > MAX_BODY_LINE_LENGTH) {
          push (@{$part_array}, substr($_, 0, MAX_BODY_LINE_LENGTH)."\n");
          substr($_, 0, MAX_BODY_LINE_LENGTH) = '';
        }
        push ( @{$part_array}, $_ );
      }
      # per rfc 1521, the CRLF before the boundary is part of the boundary:
      # NOTE: The CRLF preceding the encapsulation line is conceptually
      # attached to the boundary so that it is possible to have a part
      # that does not end with a CRLF (line break). Body parts that must
      # be considered to end with line breaks, therefore, must have two
      # CRLFs preceding the encapsulation line, the first of which is part
      # of the preceding body part, and the second of which is part of the
      # encapsulation boundary.
      elsif ($part_array) {
        chomp( $part_array->[-1] );  # trim the CRLF that's part of the boundary
        splice @{$part_array}, -1 if ( $part_array->[-1] eq '' ); # blank line for the boundary only ...
      }
      else {
        # Invalid parts can have no body, so fake in a blank body
	# in that case.
        $part_array = [];
      }

      my($p_boundary);
      ($part_msg->{'type'}, $p_boundary) = Mail::SpamAssassin::Util::parse_content_type($part_msg->header('content-type'));
      $p_boundary ||= $boundary;
      dbg("message: found part of type ".$part_msg->{'type'}.", boundary: ".(defined $p_boundary ? $p_boundary : ''));

      # we've created a new node object, so add it to the queue along with the
      # text that belongs to that part, then add the new part to the current
      # node to create the tree.
      push(@{$self->{'parse_queue'}}, [ $part_msg, $p_boundary, $part_array, $subparse ]);
      $msg->add_body_part($part_msg);

      # rfc 1521 says /^--boundary--$/, some MUAs may just require /^--boundary--/
      # but this causes problems with horizontal lines when the boundary is
      # made up of dashes as well, etc.
      if (defined $boundary) {
        # no re "strict";  # since perl 5.21.8: Ranges of ASCII printables...
        if ($line =~ /^--\Q${boundary}\E--\s*$/) {
	  # Make a note that we've seen the end boundary
	  $self->{mime_boundary_state}->{$boundary}--;
          last;
        }
	elsif ($line_count && $body->[-$line_count] !~ /^[\041-\071\073-\176]+:/) {
          # if we aren't on an end boundary and there are still lines left, it
	  # means we hit a new start boundary.  therefore, the next line ought
	  # to be a mime header.  if it's not, mark it.
	  $self->{'missing_mime_headers'} = 1;
	}
      }

      # make sure we start with a new clean node
      $in_body  = 0;
      $part_msg = Mail::SpamAssassin::Message::Node->new({ normalize=>$self->{normalize} });
      undef $part_array;
      undef $header;

      next;
    }

    if (!$in_body) {
      # s/\s+$//;   # bug 5127: don't clean this up (yet)
      # no re "strict";  # since perl 5.21.8: Ranges of ASCII printables...
      if (/^[\041-\071\073-\176]+[ \t]*:/) {
        if ($header) {
          my ( $key, $value ) = split ( /:\s*/, $header, 2 );
          $part_msg->header( $key, $value );
        }
        $header = $_;
	next;
      }
      elsif (/^[ \t]/ && $header) {
        # $_ =~ s/^\s*//;   # bug 5127, again
        $header .= $_;
	next;
      }
      else {
        if ($header) {
          my ( $key, $value ) = split ( /:\s*/, $header, 2 );
          $part_msg->header( $key, $value );
        }
        $in_body = 1;

	# if there's a blank line separator, that's good.  if there isn't,
	# it's a body line, so drop through.
	if (/^\r?$/) {
	  next;
	}
	else {
          $self->{'missing_mime_head_body_separator'} = 1;
	}
      }
    }

    # we run into a perl bug if the lines are astronomically long (probably
    # due to lots of regexp backtracking); so split any individual line
    # over MAX_BODY_LINE_LENGTH bytes in length.  This can wreck HTML
    # totally -- but IMHO the only reason a luser would use
    # MAX_BODY_LINE_LENGTH-byte lines is to crash filters, anyway.
    while (length ($_) > MAX_BODY_LINE_LENGTH) {
      push (@{$part_array}, substr($_, 0, MAX_BODY_LINE_LENGTH)."\n");
      substr($_, 0, MAX_BODY_LINE_LENGTH) = '';
    }
    push ( @{$part_array}, $_ );
  }

  # Look for a message epilogue
  # originally ignored whitespace:   0.185   0.2037   0.0654    0.757   0.00   0.00  TVD_TAB
  # ham FPs were all "." on a line by itself.
  # spams seem to only have NULL chars afterwards ?
  if ($line_count) {
    for(; $line_count > 0; $line_count--) {
      if ($body->[-$line_count] =~ /[^\s.]/) {
        $self->{mime_epilogue_exists} = 1;
        last;
      }
    }
  }

}

=item _parse_normal()

Generate a leaf node and add it to the parent.

=cut

sub _parse_normal {
  my($self, $toparse) = @_;

  my ($msg, $boundary, $body) = @{$toparse};

  dbg("message: parsing normal part");

  # 0: content-type, 1: boundary, 2: charset, 3: filename
  my @ct = Mail::SpamAssassin::Util::parse_content_type($msg->header('content-type'));

  # multipart sections are required to have a boundary set ...  If this
  # one doesn't, assume it's malformed and revert to text/plain
  $msg->{'type'} = ($ct[0] !~ m@^multipart/@i || defined $boundary ) ? $ct[0] : 'text/plain';
  $msg->{'charset'} = $ct[2];

  # attempt to figure out a name for this attachment if there is one ...
  my $disp = $msg->header('content-disposition') || '';
  if ($disp =~ /name="?([^\";]+)"?/i) {
    $msg->{'name'} = $1;
  }
  elsif ($ct[3]) {
    $msg->{'name'} = $ct[3];
  }

  $msg->{'boundary'} = $boundary;

  # If the part type is not one that we're likely to want to use, go
  # ahead and write the part data out to a temp file -- why keep sucking
  # up RAM with something we're not going to use?
  #
  if ($msg->{'type'} !~ m@^(?:text/(?:plain|html)$|message\b)@) {
    my($filepath, $fh);
    eval {
      ($filepath, $fh) = Mail::SpamAssassin::Util::secure_tmpfile();  1;
    } or do {
      my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
      info("message: failed to create a temp file: %s", $eval_stat);
    };
    if ($fh) {
      # The temp file was created, add it to the list of pending deletions
      # we cannot just delete immediately in the POSIX idiom, as this is
      # unportable (to win32 at least)
      push @{$self->{tmpfiles}}, $filepath;
      dbg("message: storing a message part to file %s", $filepath);
      $fh->print(@{$body})  or die "error writing to $filepath: $!";
      $fh->flush  or die "error writing (flush) to $filepath: $!";
      $msg->{'raw'} = $fh;
    }
  }

  # if the part didn't get a temp file, go ahead and store the data in memory
  if (!defined $msg->{'raw'}) {
    dbg("message: storing a body to memory");
    $msg->{'raw'} = $body;
  }
}

# ---------------------------------------------------------------------------

sub get_mimepart_digests {
  my ($self) = @_;

  if (!exists $self->{mimepart_digests}) {
    # traverse all parts which are leaves, recursively
    $self->{mimepart_digests} =
      [ map(sha1_hex($_->decode) . ':' . lc($_->{type}||''),
            $self->find_parts(qr/^/,1,1)) ];
  }
  return $self->{mimepart_digests};
}

# ---------------------------------------------------------------------------

# common code for get_rendered_body_text_array,
# get_visible_rendered_body_text_array, get_invisible_rendered_body_text_array
#
sub get_body_text_array_common {
  my ($self, $method_name) = @_;

  my $key = 'text_' . $method_name;
  if (exists $self->{$key}) { return $self->{$key} }

  $self->{$key} = [];

  # Find all parts which are leaves
  my @parts = $self->find_parts(qr/./,1);
  return $self->{$key} unless @parts;

  # the html metadata may have already been set, so let's not bother if it's
  # already been done.
  my $html_needs_setting = !exists $self->{metadata}->{html};

  my $text = $method_name eq 'invisible_rendered' ? ''
               : ($self->get_header('subject') || "\n");

  # Go through each part
  for (my $pt = 0 ; $pt <= $#parts ; $pt++ ) {
    my $p = $parts[$pt];

    # put a blank line between parts ...
    $text .= "\n"  if $text ne '';

    my($type, $rnd) = $p->$method_name();  # decode this part
    if ( defined $rnd ) {
      # Only text/* types are rendered ...
      $text .= $rnd;

      # TVD - if there are multiple parts, what should we do?
      # right now, just use the last one.  we may need to give some priority
      # at some point, ie: use text/html rendered if it exists, or
      # text/plain rendered as html otherwise.
      if ($html_needs_setting && $type eq 'text/html') {
        $self->{metadata}->{html} = $p->{html_results};
      }
    }
  }

  # whitespace handling (warning: small changes have large effects!)
  $text =~ s/\n+\s*\n+/\f/gs;		# double newlines => form feed
# $text =~ tr/ \t\n\r\x0b\xa0/ /s;	# whitespace (incl. VT, NBSP) => space
  $text =~ tr/ \t\n\r\x0b/ /s;		# whitespace (incl. VT) => space
  $text =~ tr/\f/\n/;			# form feeds => newline

  my @textary = split_into_array_of_short_lines($text);
  $self->{$key} = \@textary;

  return $self->{$key};
}

# ---------------------------------------------------------------------------

sub get_rendered_body_text_array {
  my ($self) = @_;
  return $self->get_body_text_array_common('rendered');
}

sub get_visible_rendered_body_text_array {
  my ($self) = @_;
  return $self->get_body_text_array_common('visible_rendered');
}

sub get_invisible_rendered_body_text_array {
  my ($self) = @_;
  return $self->get_body_text_array_common('invisible_rendered');
}

# ---------------------------------------------------------------------------

sub get_decoded_body_text_array {
  my ($self) = @_;

  if (defined $self->{text_decoded}) { return $self->{text_decoded}; }
  $self->{text_decoded} = [ ];

  # Find all parts which are leaves
  my @parts = $self->find_parts(qr/^(?:text|message)\b/i,1);
  return $self->{text_decoded} unless @parts;

  # Go through each part
  for(my $pt = 0 ; $pt <= $#parts ; $pt++ ) {
    # bug 4843: skip text/calendar parts since they're usually an attachment
    # and not displayed
    next if ($parts[$pt]->{'type'} eq 'text/calendar');

    push(@{$self->{text_decoded}}, "\n") if ( @{$self->{text_decoded}} );
    push(@{$self->{text_decoded}},
         split_into_array_of_short_paragraphs($parts[$pt]->decode()));
  }

  return $self->{text_decoded};
}

# ---------------------------------------------------------------------------

sub split_into_array_of_short_lines {
  my @result;
  foreach my $line (split (/^/m, $_[0])) {
    while (length ($line) > MAX_BODY_LINE_LENGTH) {
      # try splitting "nicely" so that we don't chop a url in half or
      # something.  if there's no space, then just split at max length.
      my $length = rindex($line, ' ', MAX_BODY_LINE_LENGTH) + 1;
      $length ||= MAX_BODY_LINE_LENGTH;
      push (@result, substr($line, 0, $length, ''));
    }
    push (@result, $line);
  }
  @result;
}

# ---------------------------------------------------------------------------

# split a text into array of paragraphs of sizes between
# $chunk_size and 2 * $chunk_size, returning the resulting array

sub split_into_array_of_short_paragraphs {
  my @result;
  my $chunk_size = 1024;
  my $text_l = length($_[0]);
  my($j,$ofs);
  for ($ofs = 0;  $text_l - $ofs > 2 * $chunk_size;  $ofs = $j+1) {
    $j = index($_[0], "\n", $ofs+$chunk_size);
    if ($j < 0) {
      $j = index($_[0], " ", $ofs+$chunk_size);
      if ($j < 0) { $j = $ofs+$chunk_size }
    }
    push(@result, substr($_[0], $ofs, $j-$ofs+1));
  }
  push(@result, substr($_[0], $ofs))  if $ofs < $text_l;
  @result;
}

# ---------------------------------------------------------------------------

1;

=back

=cut
