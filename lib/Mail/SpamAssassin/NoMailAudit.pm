# Mail message object, used by SpamAssassin.  This was written to eliminate, as
# much as possible, SpamAssassin's dependency on Mail::Audit and the
# Mail::Internet, Net::SMTP, etc. module set it requires.
#
# This is more efficient (less modules, dependencies and unused code loaded),
# and fixes some bugs found in Mail::Audit, as well as working around some
# side-effects of features of Mail::Internet that we don't use.  It's also more
# lenient about the incoming message, in the spirit of the IETF dictum 'be
# liberal in what you accept'.
#
# A regexp from Mail::Header is used.  Mail::Header is Copyright (c) 1995-2001
# Graham Barr <gbarr@pobox.com>. All rights reserved.  This program is free
# software; you can redistribute it and/or modify it under the same terms as
# Perl itself.
#
package Mail::SpamAssassin::NoMailAudit;

use Mail::SpamAssassin::Message;

@Mail::SpamAssassin::NoMailAudit::ISA = (
  	'Mail::SpamAssassin::Message'
);

# ---------------------------------------------------------------------------

sub new {
  my $class = shift;
  my %opts = @_;

  my $self = $class->SUPER::new();

  # satisfy some assumptions that callers may make about our
  # internals...
  $self->{mail_object} = $self;		# ooh confusing
  $self->{obj} = $self;			# yuck

  $self->{has_spamassassin_methods} = 1;
  $self->{headers} = { };
  $self->{header_order} = [ ];

  bless ($self, $class);

  if (defined $opts{'data'}) {
    $self->{textarray} = $opts{data};
  } else {
    $self->{textarray} = $self->read_text_array_from_stdin();
  }

  $self->parse_headers();
  return $self;
}

# ---------------------------------------------------------------------------

sub read_text_array_from_stdin {
  my ($self) = @_;

  my @ary = ();
  while (<STDIN>) {
    /^From / and $self->{from_line} = $_;
    push (@ary, $_);
    /^$/ and last;
  }

  push (@ary, (<STDIN>));
  close STDIN;

  $self->{textarray} = \@ary;
}

# ---------------------------------------------------------------------------

sub parse_headers {
  my ($self) = @_;
  local ($_);

  $self->{headers} = { };
  $self->{header_order} = [ ];
  my ($prevhdr, $hdr, $val, $entry);

  while (defined ($_ = shift @{$self->{textarray}})) {
    # warn "JMD $_";
    if (/^$/) { last; }

    $entry = $hdr = $val = undef;

    if (/^\s/) {
      if (defined $prevhdr) {
	$hdr = $prevhdr; $val = $_;
	$entry = $self->{headers}->{$hdr};
	$entry->{$entry->{count} - 1} .= $val;
	next;

      } else {
	$hdr = "X-Mail-Format-Warning";
	$val = "No previous line for continuation: $_";
	$entry = $self->_get_or_create_header_object ($hdr);
	$entry->{added} = 1;
      }

    } elsif (/^([^\x00-\x1f\x7f-\xff :]+): (.*)$/) {
      $hdr = $1; $val = $2;
      $entry = $self->_get_or_create_header_object ($hdr);
      $entry->{original} = 1;

    } else {
      $hdr = "X-Mail-Format-Warning";
      $val = "Bad RFC822 header formatting in $_";
      $entry = $self->_get_or_create_header_object ($hdr);
      $entry->{added} = 1;
    }

    $self->_add_header_to_entry ($entry, $hdr, $val);
    $prevhdr = $hdr;
  }
}

sub _add_header_to_entry {
  my ($self, $entry, $hdr, $line) = @_;

  if ($line !~ /\n$/) {
    $line .= "\n";	# ensure we have line endings
  }

  $entry->{$entry->{count}} = $line;
  push (@{$self->{header_order}}, $hdr.":".$entry->{count});
  $entry->{count}++;
}

sub _get_or_create_header_object {
  my ($self, $hdr) = @_;

  if (!defined $self->{headers}->{$hdr}) {
    $self->{headers}->{$hdr} = {
	      'count' => 0,
	      'added' => 0,
	      'original' => 0
    };
  }
  return $self->{headers}->{$hdr};
}

# ---------------------------------------------------------------------------

sub get_header {
  my ($self, $hdr) = @_;

  my $entry = $self->{headers}->{$hdr};

  if (!wantarray) {
    if (!defined $entry || $entry->{count} < 1) { return undef; }
    return $entry->{0};

  } else {
    if (!defined $entry || $entry->{count} < 1) { return ( ); }
    my @ret = ();
    foreach my $i (0 .. ($entry->{count}-1)) { push (@ret, $entry->{$i}); }
    return @ret;
  }
}

sub put_header {
  my ($self, $hdr, $text) = @_;

  my $entry = $self->_get_or_create_header_object ($hdr);
  $self->_add_header_to_entry ($entry, $hdr, $text);
  if (!$entry->{original}) { $entry->{added} = 1; }
}

sub get_all_headers {
  my ($self) = @_;

  if (!defined $self->{from_line}) {
    $self->{from_line} = "From spamassassin\@localhost  ".
    		(scalar localtime(time))."\n";
  }

  my @lines = ($self->{from_line});
  foreach my $hdrcode (@{$self->{header_order}}) {
    $hdrcode =~ /^([^:]+):(\d+)$/ or next;

    my $hdr = $1;
    my $num = $2;
    my $entry = $self->{headers}->{$hdr};
    next unless defined($entry);

    my $text = $hdr.": ".$entry->{$num};
    push (@lines, $text);
  }

  if (wantarray) {
    return @lines;
  } else {
    return join ('', @lines);
  }
}

sub replace_header {
  my ($self, $hdr, $text) = @_;

  if (!defined $self->{headers}->{$hdr}) {
    return $self->put_header($hdr, $text);
  }

  $self->{headers}->{$hdr}->{0} = $text;
}

sub delete_header {
  my ($self, $hdr) = @_;

  if (defined $self->{headers}->{$hdr}) {
    my @neworder = ();
    foreach my $hdrcode (@{$self->{header_order}}) {
      next if ($hdrcode =~ /^${hdr}:/);
      push (@neworder, $hdrcode);
    }
    @{$self->{header_order}} = @neworder;

    delete $self->{headers}->{$hdr};
  }
}

sub get_body {
  my ($self) = @_;
  return $self->{textarray};
}

sub replace_body {
  my ($self, $aryref) = @_;
  $self->{textarray} = $aryref;
}

# ---------------------------------------------------------------------------
# bonus, not-provided-in-Mail::Audit methods.

sub as_string {
  my ($self) = @_;
  return join ('', $self->get_all_headers()) . "\n" .
  		join ('', @{$self->get_body()});
}

# ---------------------------------------------------------------------------
# Mail::Audit emulation methods.

sub get { shift->get_header(@_); }
sub header { shift->get_all_headers(@_); }

sub body {
  my ($self) = shift;
  my $replacement = shift;

  if (defined $replacement) {
    $self->replace_body ($replacement);
  } else {
    return $self->get_body();
  }
}

sub ignore {
  exit (0);
}

sub print {
  my ($self, $fh) = @_;
  print $fh $self->as_string();
}

# ---------------------------------------------------------------------------

sub accept {
  my $self = shift;
  $self->_proxy_to_mail_audit ('accept', @_);
}

sub reject {
  my $self = shift;
  $self->_proxy_to_mail_audit ('reject', @_);
}

sub resend {
  my $self = shift;
  $self->_proxy_to_mail_audit ('resend', @_);
}

# ---------------------------------------------------------------------------

sub _proxy_to_mail_audit {
  my $self = shift;
  my $method = shift;
  my $ret;

  my @textary = split (/\n/s, $self->as_string());

  eval {
    require Mail::Audit;

    my %opts = ( 'data' => \@textary );
    if (exists $self->{noexit}) { $opts{noexit} = $self->{noexit}; }
    if (exists $self->{loglevel}) { $opts{loglevel} = $self->{loglevel}; }
    if (exists $self->{log}) { $opts{log} = $self->{log}; }

    my $audit = new Mail::Audit (%opts);

    if ($method eq 'accept') {
      $ret = $audit->accept (@_);
    } elsif ($method eq 'reject') {
      $ret = $audit->reject (@_);
    } elsif ($method eq 'resend') {
      $ret = $audit->resend (@_);
    }
  };

  if ($@) {
    warn "spamassassin: $method() failed, Mail::Audit ".
    		"module could not be loaded: $@";
    return undef;
  }

  return $ret;
}

# ---------------------------------------------------------------------------

sub DESTROY {
  my $self = shift;
  delete $self->{textarray};
  delete $self->{headers};
}

1;
