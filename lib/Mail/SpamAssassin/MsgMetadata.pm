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

Mail::SpamAssassin::MsgMetadata - extract metadata from a message

=head1 SYNOPSIS

=head1 DESCRIPTION

This class is tasked with extracting "metadata" from messages for use as
Bayes tokens, fodder for eval tests, or other rules.  Metadata is
supplemental data inferred from the message, like the examples below.

It is held in two forms:

1. as name-value pairs of strings, presented in mail header format.  For
  example, "X-Language" => "en".  This is the general form for simple
  metadata that's useful as Bayes tokens, can be added to marked-up
  messages using "add_header", etc., such as the trusted-relay inference
  and language detection.

2. as more complex data structures on the $msg->{metadata} object.  This
  is the form used for metadata like the HTML parse data, which is stored
  there for access by eval rule code.   Because it's not simple strings,
  it's not added as a Bayes token by default (Bayes needs simple strings).

=head1 PUBLIC METHODS

=over 4

=cut

package Mail::SpamAssassin::MsgMetadata;
use strict;
use bytes;

use Mail::SpamAssassin;
use Mail::SpamAssassin::Received;
use Mail::SpamAssassin::TextCat;

use constant MAX_BODY_LINE_LENGTH =>        2048;

=item new()

=cut

sub new {
  my ($class, $msg) = @_;
  $class = ref($class) || $class;

  my $self = {
    msg =>		$msg,
    strings =>		{ }
  };

  bless($self,$class);
  $self;
}

sub extract {
  my ($self, $msg, $main) = @_;

  # add pointers temporarily
  $self->{main} = $main;
  $self->{conf} = $main->{conf};

  # pre-chew Received headers
  $self->parse_received_headers ($msg);

  # and identify the language (if we're going to do that), before we
  # run any Bayes tests, so they can use that as a token
  $self->check_language();

  $self->{main}->call_plugins ("extract_metadata", { msg => $msg });

  # remove pointers to avoid circular refs, which break GC'ing
  delete $self->{main};
  delete $self->{conf};
}

sub finish {
  my ($self) = @_;
  delete $self->{msg};
}

# ---------------------------------------------------------------------------

sub check_language {
  my ($self) = @_;

  my @languages = split (' ', $self->{conf}->{ok_languages});
  if (grep { $_ eq "all" } @languages) {
    # user doesn't care what lang it's in, so return.
    # TODO: might want to have them as bayes tokens all the same, though.
    # should we add a new config setting to control that?  or make it a
    # plugin?
    return;
  }

  my $body = $self->get_rendered_body_text_array();
  $body = join ("\n", @{$body});
  $body =~ s/^Subject://i;

  # note body text length, since the check_languages() eval rule also
  # uses it
  $self->{languages_body_len} = length($body);

  # need about 256 bytes for reasonably accurate match (experimentally derived)
  if ($self->{languages_body_len} < 256) {
    dbg("Message too short for language analysis");
    $self->{textcat_matches} = [];
    return;
  }

  my @matches = Mail::SpamAssassin::TextCat::classify($self, $body);
  $self->{textcat_matches} = \@matches;
  my $matches_str = join(' ', @matches);

  # add to metadata so Bayes gets to take a look
  $self->{msg}->put_metadata ("X-Languages", $matches_str);

  dbg ("metadata: X-Languages: $matches_str");
}

# ---------------------------------------------------------------------------

sub get_rendered_body_text_array {
  my ($self) = @_;

  if (exists $self->{text_rendered}) { return $self->{text_rendered}; }
  local ($_);

  $self->{text_rendered} = [];

  # Find all parts which are leaves
  my @parts = $self->{msg}->find_parts(qr/^(?:text|message)\b/i,1);
  return $self->{text_rendered} unless @parts;

  # Go through each part
  my $text = $self->{msg}->get_header ('subject') || '';
  for(my $pt = 0 ; $pt <= $#parts ; $pt++ ) {
    my $p = $parts[$pt];

    my($type, $rnd) = $p->rendered(); # decode this part
    if ( defined $rnd ) {
      # Only text/* types are rendered ...
      $text .= $text ? "\n$rnd" : $rnd;

      # TVD - if there are multiple parts, what should we do?
      # right now, just use the last one ...
      $self->{html} = $p->{html_results} if ( $type eq 'text/html' );
    }
    else {
      $text .= $text ? "\n".$p->decode() : $p->decode();
    }
  }

  # whitespace handling (warning: small changes have large effects!)
  $text =~ s/\n+\s*\n+/\f/gs;                # double newlines => form feed
  $text =~ tr/ \t\n\r\x0b\xa0/ /s;        # whitespace => space
  $text =~ tr/\f/\n/;                        # form feeds => newline

  my @textary = split_into_array_of_short_lines ($text);
  $self->{text_rendered} = \@textary;

  return $self->{text_rendered};
}

# ---------------------------------------------------------------------------

sub get_decoded_body_text_array {
  my ($self) = @_;

  if (defined $self->{text_decoded}) { return $self->{text_decoded}; }

  $self->{text_decoded} = [ ];
  local ($_);

  # Find all parts which are leaves
  my @parts = $self->{msg}->find_parts(qr/./,1);
  return $self->{text_decoded} unless @parts;

  # Go through each part
  for(my $pt = 0 ; $pt <= $#parts ; $pt++ ) {
    my $p = $parts[$pt];

    # For below, we really only care about textual parts
    if ( $p->{'type'} !~ /^(?:text|message)\b/i ) {
      # remove this part from our array
      splice @parts, $pt--, 1;
      next;
    }

    $p->decode(); # decode this part
    push(@{$self->{text_decoded}}, "\n") if ( @{$self->{text_decoded}} );
    push(@{$self->{text_decoded}},
      map { split_into_array_of_short_lines($_) } @{$p->{'decoded'}} );
  }

  return $self->{text_decoded};
}

# ---------------------------------------------------------------------------

sub split_into_array_of_short_lines {
  my @result = ();
  foreach my $line (split (/^/m, $_[0])) {
    while (length ($line) > MAX_BODY_LINE_LENGTH) {
      push (@result, substr($line, 0, MAX_BODY_LINE_LENGTH));
      substr($line, 0, MAX_BODY_LINE_LENGTH) = '';
    }
    push (@result, $line);
  }
  @result;
}

# ---------------------------------------------------------------------------

#sub dbg { Mail::SpamAssassin::dbg(@_); }

1;
