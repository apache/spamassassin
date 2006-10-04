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
use bytes;

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

C<message> is either undef (which will use STDIN), a scalar of the
entire message, an array reference of the message with 1 line per array
element, or a file glob which holds the entire contents of the message.

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
  my $self = $class->SUPER::new();

  $self->{pristine_headers} =	'';
  $self->{pristine_body} =	'';
  $self->{mime_boundary_state} = {};
  $self->{line_ending} =	"\n";

  bless($self,$class);

  # create the metadata holder class
  $self->{metadata} = Mail::SpamAssassin::Message::Metadata->new($self);

  # Ok, go ahead and do the message "parsing"
  my($opts) = @_;
  my $message = $opts->{'message'} || \*STDIN;
  my $parsenow = $opts->{'parsenow'} || 0;

  # Specifies whether or not to parse message/rfc822 parts into its own tree.
  # If the # > 0, it'll subparse, otherwise it won't.  By default, do one
  # level deep.
  $self->{subparse} = defined $opts->{'subparse'} ? $opts->{'subparse'} : 20;

  # protect it from abuse ...
  local $_;

  # Figure out how the message was passed to us, and deal with it.
  my @message;
  if (ref $message eq 'ARRAY') {
     @message = @{$message};
  }
  elsif (ref $message eq 'GLOB') {
    if (defined fileno $message) {
      @message = <$message>;
    }
  }
  elsif (defined $message) {
    @message = split ( /^/m, $message );
  }

  # Pull off mbox and mbx separators
  # also deal with null messages
  if (!@message) {
    # bug 4884:
    # if we get here, it means that the input was null, so fake the message
    # content as a single newline...
    @message = ("\n");
  } elsif ($message[0] =~ /^From\s/) {
    # mbox formated mailbox
    $self->{'mbox_sep'} = shift @message;
  } elsif ($message[0] =~ MBX_SEPARATOR) {
    $_ = shift @message;

    # Munge the mbx message separator into mbox format as a sort of
    # de facto portability standard in SA's internals.  We need to
    # to this so that Mail::SpamAssassin::Util::parse_rfc822_date
    # can parse the date string...
    if (/([\s|\d]\d)-([a-zA-Z]{3})-(\d{4})\s(\d{2}):(\d{2}):(\d{2})/) {
      # $1 = day of month
      # $2 = month (text)
      # $3 = year
      # $4 = hour
      # $5 = min
      # $6 = sec
      my @arr = localtime(timelocal($6,$5,$4,$1,$MONTH{lc($2)}-1,$3));
      my $address;
      foreach (@message) {
  	if (/From:\s[^<]+<([^>]+)>/) {
  	    $address = $1;
  	    last;
  	} elsif (/From:\s([^<^>]+)/) {
  	    $address = $1;
  	    last;
  	}
      }
      $self->{'mbox_sep'} = "From $address $DAY_OF_WEEK[$arr[6]] $2 $1 $4:$5:$6 $3\n";
    }
  }

  # bug 4363
  # Check to see if we should do CRLF instead of just LF
  # For now, just check the first header and do whatever it does
  if (@message && $message[0] =~ /\r\n/) {
    $self->{line_ending} = "\r\n";
    dbg("message: line ending changed to CRLF");
  }

  # Go through all the headers of the message
  my $header = '';
  while ( my $current = shift @message ) {
    unless ($self->{'missing_head_body_separator'}) {
      $self->{'pristine_headers'} .= $current;
    }

    # NB: Really need to figure out special folding rules here!
    if ( $current =~ /^[ \t]/ ) {
      # This wasn't useful in terms of a rule, but we may want to treat it
      # specially at some point.  Perhaps ignore it?
      #unless ($current =~ /\S/) {
      #  $self->{'obsolete_folding_whitespace'} = 1;
      #}

      # append continuations if there's a header in process
      if ($header) {
        $header .= $current;
      }
    }
    else {
      # Ok, there's a header here, let's go ahead and add it in.
      if ($header) {
        # Yes, the /s is needed to match \n too.
        my ($key, $value) = split (/:\s*(?=.)/s, $header, 2);

        # If it's not a valid header (aka: not in the form "foo: bar"), skip it.
        if (defined $value) {
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

      # not a continuation...
      $header = $current;
    }

    if ($header) {
      if ($header =~ /^\r?$/) {
        last;
      }
      else {
        # Check for missing head/body separator
	# RFC 2822, s2.2:
	# A field name MUST be composed of printable US-ASCII characters
	# (i.e., characters that have values between 33 (041) and 126 (176), inclusive),
	# except colon (072).
	# FOR THIS NEXT PART: list off the valid REs for what can be next:
	#	Header, header continuation, blank line
        if (!@message || $message[0] !~ /^(?:[\041-\071\073-\176]+:|[ \t]|\r?$)/ || $message[0] =~ /^--/) {
	  # No body or no separator before mime boundary is invalid
          $self->{'missing_head_body_separator'} = 1;
	  
	  # we *have* to go back through again to make sure we catch the last
	  # header, so fake a separator and loop again.
	  unshift(@message, "\n");
        }
      }
    }
  }
  undef $header;

  # Store the pristine body for later -- store as a copy since @message
  # will get modified below
  $self->{'pristine_body'} = join('', @message);

  # CRLF -> LF
  # also merge multiple blank lines into a single one
  my $start;
  # iterate over lines in reverse order
  for (my $cnt=$#message; $cnt>=0; $cnt--) {
    $message[$cnt] =~ s/\r\n/\n/;

    # line is blank
    if ($message[$cnt] !~ /\S/) {
      if (!defined $start) {
        $start=$cnt;
      }
      next unless $cnt == 0;
    }

    # line is not blank, or we've reached the beginning

    # if we've got a series of blank lines, get rid of them
    if (defined $start) {
      my $num = $start-$cnt;
      if ($num > 10) {
        splice @message, $cnt+2, $num-1;
      }
      undef $start;
    }
  }

  # If the message does need to get parsed, save off a copy of the body
  # in a format we can easily parse later so we don't have to rip from
  # pristine_body ...  If we do want to parse now, go ahead and do so ...
  #
  if ($parsenow) {
    $self->_do_parse(\@message);
  }
  else {
    $self->{'toparse'} = \@message;
  }

  $self;
}

# ---------------------------------------------------------------------------

=item _do_parse()

Non-Public function which will initiate a MIME part parse (generates
a tree) of the current message.  Typically called by find_parts()
as necessary.

=cut

sub _do_parse {
  my($self, $array) = @_;

  # We can either be passed the array to parse, or we may have find it
  # in the object data ...
  my $toparse;
  if (defined $array) {
    $toparse = $array;
  }
  elsif (exists $self->{'toparse'}) {
    $toparse = $self->{'toparse'};
    delete $self->{'toparse'};
  }

  # If we're called when we don't need to be, then just go ahead and return.
  return if (!defined $toparse);

  dbg("message: ---- MIME PARSER START ----");

  # Figure out the boundary
  my ($boundary);
  ($self->{'type'}, $boundary) = Mail::SpamAssassin::Util::parse_content_type($self->header('content-type'));
  dbg("message: main message type: ".$self->{'type'});

  # Make the tree
  $self->parse_body( $self, $self, $boundary, $toparse, 1 );

  dbg("message: ---- MIME PARSER END ----");
}

=item find_parts()

Used to search the tree for specific MIME parts.  See
I<Mail::SpamAssassin::Message::Node> for more details.

=cut

# Used to find any MIME parts whose simple content-type matches a given regexp
# Searches it's own and any children parts.  Returns an array of MIME
# objects which match.
#
sub find_parts {
  my ($self, $re, $onlyleaves, $recursive) = @_;

  # ok, we need to do the parsing now...
  $self->_do_parse() if (exists $self->{'toparse'});

  # and pass through to the Message::Node version of the method
  return $self->SUPER::find_parts($re, $onlyleaves, $recursive);
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

Note: the returned header will include the ending newline and any embedded
whitespace folding.

=cut

sub get_pristine_header {
  my ($self, $hdr) = @_;
  
  return $self->{pristine_headers} unless $hdr;
  my(@ret) = $self->{pristine_headers} =~ /^\Q$hdr\E:[ \t]+(.*?\n(?![ \t]))/smgi;
  if (@ret) {
    return wantarray ? @ret : $ret[-1];
  }
  else {
    return $self->get_header($hdr);
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

=item extract_message_metadata($main)

=cut

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
    warn "metadata: oops! get_metadata() called after finish_metadata()"; return;
  }
  $self->{metadata}->{strings}->{$hdr};
}

=item put_metadata($hdr, $text)

=cut

sub put_metadata {
  my ($self, $hdr, $text) = @_;
  if (!$self->{metadata}) {
    warn "metadata: oops! put_metadata() called after finish_metadata()"; return;
  }
  $self->{metadata}->{strings}->{$hdr} = $text;
}

=item delete_metadata($hdr)

=cut

sub delete_metadata {
  my ($self, $hdr) = @_;
  if (!$self->{metadata}) {
    warn "metadata: oops! delete_metadata() called after finish_metadata()"; return;
  }
  delete $self->{metadata}->{strings}->{$hdr};
}

=item $str = get_all_metadata()

=cut

sub get_all_metadata {
  my ($self) = @_;

  if (!$self->{metadata}) {
    warn "metadata: oops! get_all_metadata() called after finish_metadata()"; return;
  }
  my @ret = ();
  foreach my $key (sort keys %{$self->{metadata}->{strings}}) {
    push (@ret, "$key: " . $self->{metadata}->{strings}->{$key} . "\n");
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
  undef $self->{pristine_headers};
  undef $self->{pristine_body};
  delete $self->{pristine_headers};
  delete $self->{pristine_body};
  delete $self->{text_decoded};
  delete $self->{text_rendered};

  # Destroy the tree ...
  $self->SUPER::finish();
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
  my($self, $msg, $_msg, $boundary, $body, $initial) = @_;

  # Figure out the simple content-type, or set it to text/plain
  my $type = $_msg->header('Content-Type') || 'text/plain; charset=us-ascii';

  # multipart sections are required to have a boundary set ...  If this
  # one doesn't, assume it's malformed and send it to be parsed as a
  # non-multipart section
  #
  if ( $type =~ /^multipart\//i && defined $boundary && ($msg->{subparse} > 0)) {
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

Generate a root node, and for each child part call parse_body()
to generate the tree.

=cut

sub _parse_multipart {
  my($self, $msg, $_msg, $boundary, $body) = @_;

  dbg("message: parsing multipart, got boundary: ".(defined $boundary ? $boundary : ''));

  # NOTE: The MIME boundary REs here are very specific to be mostly RFC 1521
  # compliant, but also allow possible malformations to still work.  Please
  # see Bugzilla bug 3749 for more information before making any changes!

  # ignore preamble per RFC 1521, unless there's no boundary ...
  if ( defined $boundary ) {
    my $line;
    my $tmp_line = @{$body};
    for ($line=0; $line < $tmp_line; $line++) {
      # specifically look for an opening boundary
      if ($body->[$line] =~ /^--\Q$boundary\E\s*$/) {
	# Make note that we found the opening boundary
	$self->{mime_boundary_state}->{$boundary} = 1;
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
  my $part_msg = Mail::SpamAssassin::Message::Node->new({ subparse=>$msg->{subparse}-1 });
  my $in_body = 0;
  my $header;
  my $part_array;

  my $line_count = @{$body};
  foreach ( @{$body} ) {
    # if we're on the last body line, or we find any boundary marker,
    # deal with the mime part
    if ( --$line_count == 0 || (defined $boundary && /^--\Q$boundary\E(?:--)?\s*$/) ) {
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
      $self->parse_body( $msg, $part_msg, $p_boundary, $part_array, 0 );

      # rfc 1521 says /^--boundary--$/, some MUAs may just require /^--boundary--/
      # but this causes problems with horizontal lines when the boundary is
      # made up of dashes as well, etc.
      if (defined $boundary && $line =~ /^--\Q${boundary}\E--\s*$/) {
	# Make a note that we've seen the end boundary
	$self->{mime_boundary_state}->{$boundary}--;
        last;
      }

      # make sure we start with a new clean node
      $in_body  = 0;
      $part_msg = Mail::SpamAssassin::Message::Node->new({ subparse=>$msg->{subparse}-1 });
      undef $part_array;
      undef $header;

      next;
    }

    if (!$in_body) {
      s/\s+$//;
      if (m/^[\041-\071\073-\176]+:/) {
        if ($header) {
          my ( $key, $value ) = split ( /:\s*/, $header, 2 );
          $part_msg->header( $key, $value );
        }
        $header = $_;
	next;
      }
      elsif (/^[ \t]/) {
        $_ =~ s/^\s*//;
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
    # due to lots of regexp backtracking); so cut short any individual line
    # over MAX_BODY_LINE_LENGTH bytes in length.  This can wreck HTML
    # totally -- but IMHO the only reason a luser would use
    # MAX_BODY_LINE_LENGTH-byte lines is to crash filters, anyway.
    while (length ($_) > MAX_BODY_LINE_LENGTH) {
      push (@{$part_array}, substr($_, 0, MAX_BODY_LINE_LENGTH)."\n");
      substr($_, 0, MAX_BODY_LINE_LENGTH) = '';
    }
    push ( @{$part_array}, $_ );
  }

}

=item _parse_normal()

Generate a leaf node and add it to the parent.

=cut

sub _parse_normal {
  my ($self, $msg, $part_msg, $boundary, $body) = @_;

  dbg("message: parsing normal part");

  # 0: content-type, 1: boundary, 2: charset, 3: filename
  my @ct = Mail::SpamAssassin::Util::parse_content_type($part_msg->header('content-type'));
  $part_msg->{'type'} = $ct[0];

  # multipart sections are required to have a boundary set ...  If this
  # one doesn't, assume it's malformed and revert to text/plain
  $part_msg->{'type'} = 'text/plain' if ( $part_msg->{'type'} =~ /^multipart\//i && !defined $boundary );

  # attempt to figure out a name for this attachment if there is one ...
  my $disp = $part_msg->header('content-disposition') || '';
  if ($disp =~ /name="?([^\";]+)"?/i) {
    $part_msg->{'name'} = $1;
  }
  elsif ($ct[3]) {
    $part_msg->{'name'} = $ct[3];
  }

  $part_msg->{'raw'} = $body;
  $part_msg->{'boundary'} = $boundary;

  # If this part is a message/* part, and the parent isn't also a
  # message/* part (ie: the main part) go ahead and parse into a tree.
  if ($part_msg->{'type'} =~ /^message\b/i && ($msg->{subparse} > 0)) {
    # Get the part ready...
    my $message = $part_msg->decode();

    if ($message) {
      my $msg_obj = Mail::SpamAssassin::Message->new({
      	message		=>	$message,
	parsenow	=>	1,
	subparse	=>	$msg->{subparse}-1,
	});

      # main message is a message/* part ...
      if ($msg == $part_msg) {
        $msg->add_body_part($msg_obj);
      }
      else {
        # Add the new part as a child to the parent
        # NOTE: if the message only has this one part, we'll be recursive so delete
        # the body_parts list appropriately.
        $msg->add_body_part($part_msg);

        $part_msg->add_body_part($msg_obj);
      }

      return;
    }
  }
  else {
    # leaves don't need the subparse value, so get rid of it
    delete $part_msg->{subparse};
  }

  # Add the new part as a child to the parent
  # NOTE: if the message only has this one part, we'll be recursive so delete
  # the body_parts list appropriately.
  $msg->add_body_part($part_msg);

  # now that we've added the leaf node, let's go ahead and kill
  # body_parts (used for sub-trees).  there's no point for a leaf to have it,
  # and if the main and child parts are the same, we'll end up being recursive,
  # and well, let's avoid that. ;)
  #
  # BTW: please leave this after add_body_parts() since it'll add it back.
  #
  delete $part_msg->{body_parts};
}

# ---------------------------------------------------------------------------

sub get_rendered_body_text_array {
  my ($self) = @_;

  if (exists $self->{text_rendered}) { return $self->{text_rendered}; }

  $self->{text_rendered} = [];

  # Find all parts which are leaves
  my @parts = $self->find_parts(qr/^(?:text|message)\b/i,1);
  return $self->{text_rendered} unless @parts;

  # the html metadata may have already been set, so let's not bother if it's
  # already been done.
  my $html_needs_setting = !exists $self->{metadata}->{html};

  # Go through each part
  my $text = $self->get_header ('subject') || '';
  for(my $pt = 0 ; $pt <= $#parts ; $pt++ ) {
    my $p = $parts[$pt];

    # bug 4843: skip text/calendar parts since they're usually an attachment
    # and not displayed
    next if ($p->{'type'} eq 'text/calendar');

    # put a blank line between parts ...
    $text .= "\n" if ( $text );

    my($type, $rnd) = $p->rendered(); # decode this part
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
    else {
      $text .= $p->decode();
    }
  }

  # whitespace handling (warning: small changes have large effects!)
  $text =~ s/\n+\s*\n+/\f/gs;		# double newlines => form feed
  $text =~ tr/ \t\n\r\x0b\xa0/ /s;	# whitespace => space
  $text =~ tr/\f/\n/;			# form feeds => newline
  
  # warn "message: $text";

  my @textary = split_into_array_of_short_lines ($text);
  $self->{text_rendered} = \@textary;

  return $self->{text_rendered};
}

# ---------------------------------------------------------------------------

# TODO: possibly this should just replace get_rendered_body_text_array().
# (although watch out, this one doesn't copy {html} to metadata)
sub get_visible_rendered_body_text_array {
  my ($self) = @_;

  if (exists $self->{text_visible_rendered}) {
    return $self->{text_visible_rendered};
  }

  $self->{text_visible_rendered} = [];

  # Find all parts which are leaves
  my @parts = $self->find_parts(qr/^(?:text|message)\b/i,1);
  return $self->{text_visible_rendered} unless @parts;

  # the html metadata may have already been set, so let's not bother if it's
  # already been done.
  my $html_needs_setting = !exists $self->{metadata}->{html};

  # Go through each part
  my $text = $self->get_header ('subject') || '';
  for(my $pt = 0 ; $pt <= $#parts ; $pt++ ) {
    my $p = $parts[$pt];

    # bug 4843: skip text/calendar parts since they're usually an attachment
    # and not displayed
    next if ($p->{'type'} eq 'text/calendar');

    # put a blank line between parts ...
    $text .= "\n" if ( $text );

    my($type, $rnd) = $p->visible_rendered(); # decode this part
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
    else {
      $text .= $p->decode();
    }
  }

  # whitespace handling (warning: small changes have large effects!)
  $text =~ s/\n+\s*\n+/\f/gs;		# double newlines => form feed
  $text =~ tr/ \t\n\r\x0b\xa0/ /s;	# whitespace => space
  $text =~ tr/\f/\n/;			# form feeds => newline

  my @textary = split_into_array_of_short_lines ($text);
  $self->{text_visible_rendered} = \@textary;

  return $self->{text_visible_rendered};
}

sub get_invisible_rendered_body_text_array {
  my ($self) = @_;

  if (exists $self->{text_invisible_rendered}) {
    return $self->{text_invisible_rendered};
  }

  $self->{text_invisible_rendered} = [];

  # Find all parts which are leaves
  my @parts = $self->find_parts(qr/^(?:text|message)\b/i,1);
  return $self->{text_invisible_rendered} unless @parts;

  # the html metadata may have already been set, so let's not bother if it's
  # already been done.
  my $html_needs_setting = !exists $self->{metadata}->{html};

  # Go through each part
  my $text = '';
  for(my $pt = 0 ; $pt <= $#parts ; $pt++ ) {
    my $p = $parts[$pt];

    # bug 4843: skip text/calendar parts since they're usually an attachment
    # and not displayed
    next if ($p->{'type'} eq 'text/calendar');

    # put a blank line between parts ...
    $text .= "\n" if ( $text );

    my($type, $rnd) = $p->invisible_rendered(); # decode this part
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
  $text =~ tr/ \t\n\r\x0b\xa0/ /s;	# whitespace => space
  $text =~ tr/\f/\n/;			# form feeds => newline

  my @textary = split_into_array_of_short_lines ($text);
  $self->{text_invisible_rendered} = \@textary;

  return $self->{text_invisible_rendered};
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
    push(@{$self->{text_decoded}}, split_into_array_of_short_lines($parts[$pt]->decode()));
  }

  return $self->{text_decoded};
}

# ---------------------------------------------------------------------------

sub split_into_array_of_short_lines {
  my @result = ();
  foreach my $line (split (/^/m, $_[0])) {
    while (length ($line) > MAX_BODY_LINE_LENGTH) {
      # try splitting "nicely" so that we don't chop an url in half or
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

1;

=back

=cut
