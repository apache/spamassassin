=head1 NAME

Hashcash - add message metadata indicating the country code of each relay

=head1 SYNOPSIS

  loadplugin     Mail::SpamAssassin::Plugin::Hashcash

=cut

package Mail::SpamAssassin::Plugin::Hashcash;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::SHA1 qw(sha1);
use Fcntl;
use File::Path;
use File::Basename;
use strict;
use bytes;

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

use constant HAS_DB_FILE => eval { require DB_File; };

# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  my $conf = $mailsaobject->{conf};
  $conf->{use_hashcash} = 1;
  $conf->{hashcash_accept} = { };
  $conf->{hashcash_doublespend_path} = '__userstate__/hashcash_seen';
  $conf->{hashcash_doublespend_file_mode} = "0700";

  $self->register_eval_rule ("check_hashcash_value");
  $self->register_eval_rule ("check_hashcash_double_spend");

  return $self;
}

###########################################################################

sub parse_config {
  my ($self, $opts) = @_;
  my $conf = $opts->{conf};
  my $key = $opts->{key};
  my $value = $opts->{value};

=item use_hashcash { 1 | 0 }   (default: 1)

Whether to use hashcash, if it is available.

=cut

  if ( $key eq 'use_hashcash' ) {
    $conf->{use_hashcash} = $value+0; return 1;
  }

=item hashcash_accept add@ress.com ...

Used to specify addresses that we accept HashCash tokens for.  You should set
it to match all the addresses that you may receive mail at.

Like whitelist and blacklist entries, the addresses are file-glob-style
patterns, so C<friend@somewhere.com>, C<*@isp.com>, or C<*.domain.net> will all
work.  Specifically, C<*> and C<?> are allowed, but all other metacharacters
are not.  Regular expressions are not used for security reasons.

The sequence C<%u> is replaced with the current user's username, which
is useful for ISPs or multi-user domains.

Multiple addresses per line, separated by spaces, is OK.  Multiple
C<hashcash_accept> lines is also OK.

=cut

  if ( $key eq 'hashcash_accept' ) {
    $conf->add_to_addrlist ('hashcash_accept', split (/\s+/, $value)); return 1;
  }

=item hashcash_doublespend_path /path/to/file   (default: ~/.spamassassin/hashcash_seen)

Path for HashCash double-spend database.  HashCash tokens are only usable once,
so their use is tracked in this database to avoid providing a loophole.

By default, each user has their own, in their C<~/.spamassassin> directory with
mode 0700/0600.  Note that once a token is 'spent' it is written to this file,
and double-spending of a hashcash token makes it invalid, so this is not
suitable for sharing between multiple users.

=cut

  if ( $key eq 'hashcash_doublespend_path' ) {
    $conf->{hashcash_doublespend_path} = $value; return 1;
  }

=item hashcash_doublespend_file_mode            (default: 0700)

The file mode bits used for the HashCash double-spend database file.

Make sure you specify this using the 'x' mode bits set, as it may also be used
to create directories.  However, if a file is created, the resulting file will
not have any execute bits set (the umask is set to 111).

=cut

  if ( $key eq 'hashcash_doublespend_file_mode' ) {
    $conf->{hashcash_doublespend_file_mode} = $value+0; return 1;
  }

  return 0;
}

###########################################################################

sub check_hashcash_value {
  my ($self, $scanner, $valmin, $valmax) = @_;
  my $val = $self->_run_hashcash($scanner);
  return ($val >= $valmin && $val < $valmax);
}

sub check_hashcash_double_spend {
  my ($self, $scanner) = @_;
  $self->_run_hashcash($scanner);
  return ($scanner->{hashcash_double_spent});
}

############################################################################

sub _run_hashcash {
  my ($self, $scanner) = @_;

  if (defined $scanner->{hashcash_value}) { return $scanner->{hashcash_value}; }

  $scanner->{hashcash_value} = 0;
  my $hc = $scanner->get ("X-Hashcash");
  # X-Hashcash: 0:031118:camram-spam@camram.org:c068b58ade6dcbaf

  if (!$hc) { return 0; }

  # untaint the string for paranoia, making sure not to allow \n \0 \' \"
  $hc =~ /^([-A-Za-z0-9\xA0-\xFF:_\/\%\@\.\,\= \*\+]+)$/; $hc = $1;
  if (!$hc) { return 0; }

  my ($ver, $date, $rsrc, $trial);
  ($ver, $date, $rsrc, $trial) = ($hc =~ /(\S+):(\S+):(\S+):(\S+)/ );
  if (!$trial) { return 0; }

  my $accept = $scanner->{conf}->{hashcash_accept};
  if (!$self->_check_hashcash_resource ($scanner, $accept, $rsrc)) {
    dbg ("hashcash: resource $rsrc not accepted here");
    return 0;
  }

  # get the hash collision from the token.  Computing the hash collision
  # is very easy (great!) -- just get SHA1(token) and count the 0 bits at
  # the start of the SHA1 hash, according to the draft at
  # http://www.hashcash.org/draft-hashcash.txt .
  my $value = 0;
  my $bitstring = unpack ("B*", pack ("H*", sha1($hc)));
  $bitstring =~ /^(0+)/ and $value = length $1;

  dbg ("hashcash token value: $value");

  if ($self->was_hashcash_token_double_spent ($scanner, $hc)) {
    $scanner->{hashcash_double_spent} = 1;
    return 0;
  }

  $scanner->{hashcash_value} = $value;
  return $value;
}

sub was_hashcash_token_double_spent {
  my ($self, $scanner, $token) = @_;

  my $main = $self->{main};
  if (!$main->{conf}->{hashcash_doublespend_path}) {
    dbg ("hashcash_doublespend_path not defined or empty");
    return 0;
  }
  if (!HAS_DB_FILE) {
    dbg ("hashcash: DB_File module not installed, cannot use double-spend db");
    return 0;
  }

  my $path = $main->sed_path ($main->{conf}->{hashcash_doublespend_path});
  my $parentdir = dirname ($path);
  if (!-d $parentdir) {
    # run in an eval(); if mkpath has no perms, it calls die()
    eval {
      mkpath ($parentdir, 0, (oct ($main->{conf}->{hashcash_doublespend_file_mode}) & 0777));
    };
  }

  my %spenddb;
  if (!tie %spenddb, "DB_File", $path, O_RDWR|O_CREAT,
                (oct ($main->{conf}->{hashcash_doublespend_file_mode}) & 0666))
  {
    dbg ("hashcash: failed to tie to $path: $@ $!");
    # not a serious error. TODO?
    return 0;
  }

  if (exists $spenddb{$token}) {
    dbg ("hashcash: token '$token' spent already");
    return 1;
  }

  $spenddb{$token} = time;
  dbg ("hashcash: marking token '$token' as spent");

  # TODO: expiry?

  untie %spenddb;

  return 0;
}

sub _check_hashcash_resource {
  my ($self, $scanner, $list, $addr) = @_;
  $addr = lc $addr;
  if (defined ($list->{$addr})) { return 1; }
  study $addr;

  foreach my $regexp (values %{$list})
  {
    # allow %u == current username
    $regexp =~ s/\%u/$scanner->{main}->{username}/gs;

    if ($addr =~ /$regexp/i) {
      return 1;
    }
  }

  # TODO: use "To" and "Cc" addresses gleaned from the mails in the Bayes
  # database trained as ham, as well.

  return 0;
}

############################################################################

sub dbg { Mail::SpamAssassin::dbg (@_); }

1;
