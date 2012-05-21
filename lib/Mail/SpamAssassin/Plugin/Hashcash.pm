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

Mail::SpamAssassin::Plugin::Hashcash - perform hashcash verification tests

=head1 SYNOPSIS

  loadplugin     Mail::SpamAssassin::Plugin::Hashcash

=head1 DESCRIPTION

Hashcash is a payment system for email where CPU cycles used as the
basis for an e-cash system.  This plugin makes it possible to use valid
hashcash tokens added by mail programs as a bonus for messages.

=cut

=head1 USER SETTINGS

=over 4

=item use_hashcash { 1 | 0 }   (default: 1)

Whether to use hashcash, if it is available.

=cut

=item hashcash_accept user@example.com ...

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

=item hashcash_doublespend_path /path/to/file   (default: ~/.spamassassin/hashcash_seen)

Path for HashCash double-spend database.  HashCash tokens are only usable once,
so their use is tracked in this database to avoid providing a loophole.

By default, each user has their own, in their C<~/.spamassassin> directory with
mode 0700/0600.  Note that once a token is 'spent' it is written to this file,
and double-spending of a hashcash token makes it invalid, so this is not
suitable for sharing between multiple users.

=cut

=item hashcash_doublespend_file_mode            (default: 0700)

The file mode bits used for the HashCash double-spend database file.

Make sure you specify this using the 'x' mode bits set, as it may also be used
to create directories.  However, if a file is created, the resulting file will
not have any execute bits set (the umask is set to 111).

=cut

package Mail::SpamAssassin::Plugin::Hashcash;

use strict;
use warnings;
use bytes;
use re 'taint';

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Util qw(untaint_var);

use Errno qw(ENOENT EACCES);
use Fcntl;
use File::Path;
use File::Basename;

BEGIN {
  eval { require Digest::SHA; import Digest::SHA qw(sha1); 1 }
  or do { require Digest::SHA1; import Digest::SHA1 qw(sha1) }
}

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

  $self->register_eval_rule ("check_hashcash_value");
  $self->register_eval_rule ("check_hashcash_double_spend");

  $self->set_config($mailsaobject->{conf});

  return $self;
}

###########################################################################

sub set_config {
  my($self, $conf) = @_;
  my @cmds;

  push(@cmds, {
    setting => 'use_hashcash',
    default => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });

  push(@cmds, {
    setting => 'hashcash_doublespend_path',
    default => '__userstate__/hashcash_seen',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
  });

  push(@cmds, {
    setting => 'hashcash_doublespend_file_mode',
    default => "0700",
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });

  push(@cmds, {
    setting => 'hashcash_accept',
    default => {},
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_ADDRLIST,
  });

  $conf->{parser}->register_commands(\@cmds);
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

  # X-Hashcash: 0:031118:camram-spam@camram.org:c068b58ade6dcbaf
  # or:
  # X-hashcash: 1:20:040803:hashcash@freelists.org::6dcdb3a3ad4e1b86:1519d
  # X-hashcash: 1:20:040803:jm@jmason.org::6b484d06469ccb28:8838a
  # X-hashcash: 1:20:040803:adam@cypherspace.org::a1cbc54bf0182ea8:5d6a0

  # call down to {msg} so that we can get it as an array of
  # individual headers
  my @hdrs = $scanner->{msg}->get_header ("X-Hashcash");
  if (scalar @hdrs == 0) {
    @hdrs = $scanner->{msg}->get_header ("Hashcash");
  }

  foreach my $hc (@hdrs) {
    my $value = $self->_run_hashcash_for_one_string($scanner, $hc);
    if ($value) {
      # remove the "double-spend" bool if we did find a usable string;
      # this happens when one string is already spent, but another
      # string has not yet been.
      delete $scanner->{hashcash_double_spent};
      return $value;
    }
  }
  return 0;
}

sub _run_hashcash_for_one_string {
  my ($self, $scanner, $hc) = @_;

  if (!$hc) { return 0; }
  $hc =~ s/\s+//gs;       # remove whitespace from multiline, folded tokens

  # untaint the string for paranoia, making sure not to allow \n \0 \' \"
  if ($hc =~ /^[-A-Za-z0-9\xA0-\xFF:_\/\%\@\.\,\= \*\+\;]+$/) {
    $hc = untaint_var($hc);
  }
  if (!$hc) { return 0; }

  my ($ver, $bits, $date, $rsrc, $exts, $rand, $trial);
  if ($hc =~ /^0:/) {
    ($ver, $date, $rsrc, $trial) = split (/:/, $hc, 4);
  }
  elsif ($hc =~ /^1:/) {
    ($ver, $bits, $date, $rsrc, $exts, $rand, $trial) =
                                    split (/:/, $hc, 7);
    # extensions are, as yet, unused by SpamAssassin
  }
  else {
    dbg("hashcash: version $ver stamps not yet supported");
    return 0;
  }

  if (!$trial) {
    dbg("hashcash: no trial in stamp '$hc'");
    return 0;
  }

  my $accept = $scanner->{conf}->{hashcash_accept};
  if (!$self->_check_hashcash_resource ($scanner, $accept, $rsrc)) {
    dbg("hashcash: resource $rsrc not accepted here");
    return 0;
  }

  # get the hash collision from the token.  Computing the hash collision
  # is very easy (great!) -- just get SHA1(token) and count the 0 bits at
  # the start of the SHA1 hash, according to the draft at
  # http://www.hashcash.org/draft-hashcash.txt .
  my $value = 0;
  my $bitstring = unpack ("B*", sha1($hc));
  $bitstring =~ /^(0+)/ and $value = length $1;

  # hashcash v1 tokens: if the "claimed value" of the token is less than
  # what the token actually contains (ie. token was accidentally generated
  # with 24 bits instead of the claimed 20), then cut it down to just the
  # claimed value.  that way it's a bit tidier and more deterministic.
  if ($bits && $value > $bits) {
    $value = $bits;
  }

  dbg("hashcash: token value: $value");

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
    dbg("hashcash: hashcash_doublespend_path not defined or empty");
    return 0;
  }
  if (!HAS_DB_FILE) {
    dbg("hashcash: DB_File module not installed, cannot use double-spend db");
    return 0;
  }

  my $path = $main->sed_path ($main->{conf}->{hashcash_doublespend_path});
  my $parentdir = dirname ($path);
  my $stat_errn = stat($parentdir) ? 0 : 0+$!;
  if ($stat_errn == 0 && !-d _) {
    dbg("hashcash: parent dir $parentdir exists but is not a directory");
  } elsif ($stat_errn == ENOENT) {
    # run in an eval(); if mkpath has no perms, it calls die()
    eval {
      mkpath ($parentdir, 0, (oct ($main->{conf}->{hashcash_doublespend_file_mode}) & 0777));
    };
  }

  my %spenddb;
  if (!tie %spenddb, "DB_File", $path, O_RDWR|O_CREAT,
                (oct ($main->{conf}->{hashcash_doublespend_file_mode}) & 0666))
  {
    dbg("hashcash: failed to tie to $path: $@ $!");
    # not a serious error. TODO?
    return 0;
  }

  if (exists $spenddb{$token}) {
    untie %spenddb;
    dbg("hashcash: token '$token' spent already");
    return 1;
  }

  $spenddb{$token} = time;
  dbg("hashcash: marking token '$token' as spent");

  # TODO: expiry?

  untie %spenddb;

  return 0;
}

sub _check_hashcash_resource {
  my ($self, $scanner, $list, $addr) = @_;
  $addr = lc $addr;
  if (defined ($list->{$addr})) { return 1; }
  study $addr;  # study is a no-op since perl 5.16.0, eliminating related bugs

  foreach my $regexp (values %{$list})
  {
    # allow %u == current username
    # \\ is added by $conf->add_to_addrlist()
    $regexp =~ s/\\\%u/$scanner->{main}->{username}/gs;

    if ($addr =~ /$regexp/i) {
      return 1;
    }
  }

  # TODO: use "To" and "Cc" addresses gleaned from the mails in the Bayes
  # database trained as ham, as well.

  return 0;
}

############################################################################

1;

=back

=cut
