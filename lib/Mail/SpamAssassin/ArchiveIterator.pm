#!/usr/bin/perl -w
#
# iterate over mail archives, calling a function on each message.

package Mail::SpamAssassin::ArchiveIterator;
use strict;
eval "use bytes";

use vars qw{ @ISA };

@ISA = qw();

###########################################################################

sub new {
  my $class = shift;
  $class = ref($class) || $class;

  my $self = shift;
  if (!defined $self) { $self = { }; }
  bless ($self, $class);

  $self->{count} = 0;
  $self;
}

###########################################################################

=item $iterator->set_function ( \&wanted );

Set the visitor function.

=cut

sub set_function {
  my ($self, $fn) = @_;
  $self->{wanted_sub} = $fn;
}

###########################################################################

=item $iterator->run ("folderpath" [, ...] )

Iterate over the named folders.  If no folders are named, B<('-')> is assumed;
in other words, a single mail message on STDIN.

=cut

sub run {
  my $self = shift;

  if (!defined $self->{wanted_sub}) {
    die "set_function never called";
  }

  if ($#_ < 0) { @_ = ('-'); }

  foreach my $folder (@_) {
    if ($folder =~ /\.tar$/)
    {
	# it's an MH or Cyrus folder or Maildir in a tar file
	require Archive::Tar;   # jm: require avoids warning
	$self->mass_check_tar_file($folder);
    }
    elsif (-d $folder && -d "$folder/cur" && -d "$folder/new" )
    {
      # Maildir!
      $self->mass_check_maildir($folder);
    }
    elsif (-d $folder)
    {
      # it's an MH folder or a Cyrus mailbox
      # not necessary to check this: just assume it's MH/Cyrus. if we
      # do these conditions, a non-packed MH folder will be ignored silently
      #($self->{opt_mh} || -f "$folder/1" || -f "$folder/1.gz" || -f "$folder/cyrus.index"))
      $self->mass_check_mh_folder($folder);
    }
    elsif ($folder eq '-' || (-f $folder && $self->{opt_single}))
    {
      # single message (for testing that variables are cleared appropriately)
      $self->mass_check_single($folder);
    }
    elsif (-f $folder) {
      $self->mass_check_mailbox($folder);
    }
  }
}

sub mass_check_tar_file {
  my $self = shift;
  my $filename = shift;
  my $tar = Archive::Tar->new();
  $tar->read($filename);
  my @files = $tar->list_files(['name']);
  foreach my $mail (@files) {
      next if $mail =~ m#/$# or $mail =~ /cyrus\.(index|header|cache)/;
      my $msg_data = $tar->get_content($mail);
      my @msg = split("\n",$tar->get_content($mail));
      $mail =~ s/\s/_/g;

      $self->visit_a_mail ($mail, \@msg);
  }
}

sub mass_check_mh_folder {
  my $self = shift;
  my $folder = shift;
  opendir(DIR, $folder) || die "Can't open $folder dir: $!";
  my @files = grep { -f } map { "$folder/$_" } grep { /^[0-9]/ } readdir(DIR);
  closedir(DIR);

  @files = sortbynum(@files) if $self->{opt_sort};
  splice(@files, $self->{opt_head}) if $self->{opt_head};
  splice(@files, 0, -$self->{opt_tail}) if $self->{opt_tail};
  foreach my $mail (@files)
  {
    if ($mail =~ /\.gz$/) {
      open (STDIN, "gunzip -cd $mail |") or warn "gunzip $mail failed: $@";
    } elsif ($mail =~ /\.bz2$/) {
      open (STDIN, "bzip2 -cd $mail |") or warn "bunzip2 $mail failed: $@";
    } else {
      open (STDIN, "<$mail") or warn "open $mail failed: $@";
    }

    # skip too-big mails
    if (! $self->{opt_all} && -s STDIN > 250*1024) { close STDIN; next; }
    my @msg = (<STDIN>);
    close STDIN;

    $self->visit_a_mail ($mail, \@msg);
  }
}

sub mass_check_maildir {
  my $self = shift;
  my $folder = shift;
  opendir(CURDIR, "$folder/cur") || die "Can't open $folder/cur dir: $!";
  opendir(NEWDIR, "$folder/new") || die "Can't open $folder/new dir: $!";
  my @files;
  push @files, grep { -f } map { "$folder/cur/$_" } readdir(CURDIR);
  push @files, grep { -f } map { "$folder/new/$_" } readdir(NEWDIR);
  closedir(CURDIR);
  closedir(NEWDIR);

  @files = sortbynum(@files) if $self->{opt_sort};
  splice(@files, $self->{opt_head}) if $self->{opt_head};
  splice(@files, 0, -$self->{opt_tail}) if $self->{opt_tail};
  foreach my $mail (@files)
  {
    if ($mail =~ /\.gz$/) {
      open (STDIN, "gunzip -cd $mail |") or warn "gunzip $mail failed: $@";
    } elsif ($mail =~ /\.bz2$/) {
      open (STDIN, "bzip2 -cd $mail |") or warn "bunzip2 $mail failed: $@";
    } else {
      open (STDIN, "<$mail") or warn "open $mail failed: $@";
    }

    # skip too-big mails
    if (! $self->{opt_all} && -s STDIN > 250*1024) { close STDIN; next; }
    my @msg = (<STDIN>);
    close STDIN;

    $self->visit_a_mail ($mail, \@msg);
  }
}

sub mass_check_single {
  my $self = shift;
  my $folder = shift;

  if ($folder =~ /\.gz$/) {
    open (STDIN, "gunzip -cd $folder |") or warn "gunzip $folder failed: $@";
  } elsif ($folder =~ /\.bz2$/) {
    open (STDIN, "bzip2 -cd $folder |") or warn "bunzip2 $folder failed: $@";
  } elsif ($folder eq '-') {
    # do nothing; it's on STDIN
  } else {
    open (STDIN, "<$folder") or warn "open $folder failed: $@";
  }

  # skip too-big mails
  if (! $self->{opt_all} && -s STDIN > 250*1024) {
    warn "Skipping message, too large (>250k)";
    return;
  }
  my @msg = (<STDIN>);

  $self->visit_a_mail ($folder, \@msg);
}

sub mass_check_mailbox {
  my $self = shift;
  my $folder = shift;

  if ($folder =~ /\.gz$/) {
    open (MBOX, "gunzip -cd $folder |") or warn "gunzip $folder failed: $@";
  } elsif ($folder =~ /\.bz2$/) {
    open (MBOX, "bzip2 -cd $folder |") or warn "bunzip2 $folder failed: $@";
  } else {
    open (MBOX, "<$folder") or warn "open $folder failed: $@";
  }
  while (<MBOX>) { /^From \S+ +... ... / and last; }

  my $count = 0;
  my $host  = $ENV{'HOSTNAME'} || $ENV{'HOST'} || `hostname` || 'localhost';

  while (!eof MBOX) {
    my @msg = ();
    my $in_header = 1;
    my $msgid = undef;
    my $hits = '';
    $count++;

    while (<MBOX>) {
      if (/^$/ && $in_header) {
        $in_header = 0 ;

        if (!defined ($msgid)) {
          $msgid = sprintf('<no-msgid-in-msg-%06d@%s.masses.spamassasin.org>', $count, $host);
          push (@msg, "Message-Id: $msgid\n");
        }
      }
      if ($in_header) {
        /^Message-Id: (.*?)\s*$/i        and $msgid = $1;
        /^X-Spam-Status: .* tests=(.*)$/ and $hits  = $1;
      }

      /^From \S+ +... ... / and last;
      push (@msg, $_);
    }

    next unless (@msg);                                 # skip empty,
    next if (! $self->{opt_all} && $in_header);         # broken and
    next if (! $self->{opt_all} && scalar @msg > 1000); # too big messages

    $msgid ||= "(undef)";
    $msgid = "$folder:$msgid";	# so we can find it again
    $msgid =~ s/\s/_/gs;	# make safe

    # switch to a fork-based model to save RAM
    if ($self->{opt_fork} && fork()) { wait; next; }
    $self->visit_a_mail ($msgid, \@msg);
    if ($self->{opt_fork}) { exit; }
  }

  close MBOX;
}

############################################################################

sub sortbynum {
    return map { $_->[0] }
	sort { $a->[1] <=> $b->[1] } map { [$_, /\/(\d+).*$/] } @_;
}

############################################################################

sub visit_a_mail {
  my ($self, $mail, $dataref) = @_;
  my $sub = $self->{wanted_sub};
  return &$sub ($mail, $dataref);
}

############################################################################

1;
