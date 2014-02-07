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

Mail::SpamAssassin::AICache - provide access to cached information for
ArchiveIterator

=head1 SYNOPSIS

=head1 DESCRIPTION

This module allows ArchiveIterator to use cached atime information instead of
having to read every message separately.

=head1 PUBLIC METHODS

=over 4

=cut

package Mail::SpamAssassin::AICache;

use File::Spec;
use File::Path;
use File::Basename;
use Mail::SpamAssassin::Logger;

use strict;
use warnings;
use re 'taint';
use Errno qw(EBADF);

=item new()

Generates a new cache object.

=back

=cut

sub new {
  my $class = shift;
  $class = ref($class) || $class;

  my $self = shift;
  if (!defined $self) { $self = {}; }

  $self->{cache} = {};
  $self->{dirty} = 0;
  $self->{prefix} ||= '/';

  my $use_cache = 1;

  # be sure to use rel2abs() here, since otherwise relative paths
  # are broken by the prefix stuff
  if ($self->{type} eq 'dir') {
    $self->{cache_file} = File::Spec->catdir(
                $self->{prefix},
                File::Spec->rel2abs($self->{path}),
                '.spamassassin_cache');

    my @stat = stat($self->{cache_file});
    @stat  or dbg("AIcache: no access to %s: %s", $self->{cache_file}, $!);
    $self->{cache_mtime} = $stat[9] || 0;
  }
  else {
    my @split = File::Spec->splitpath($self->{path});
    $self->{cache_file} = File::Spec->catdir(
                $self->{prefix},
                File::Spec->rel2abs($split[1]),
                join('_', '.spamassassin_cache', $self->{type}, $split[2]));

    my @stat = stat($self->{cache_file});
    @stat  or dbg("AIcache: no access to %s: %s", $self->{cache_file}, $!);
    $self->{cache_mtime} = $stat[9] || 0;

    # for mbox and mbx, verify whether mtime on cache file is >= mtime of
    # messages file.  if it is, use it, otherwise don't.
    @stat = stat($self->{path});
    @stat  or dbg("AIcache: no access to %s: %s", $self->{path}, $!);
    if ($stat[9] > $self->{cache_mtime}) {
      $use_cache = 0;
    }
  }
  $self->{cache_file} = File::Spec->canonpath($self->{cache_file});

  # go ahead and read in the cache information
  local *CACHE;
  if (!$use_cache) {
    # not in use
  } elsif (!open(CACHE, $self->{cache_file})) {
    dbg("AIcache: cannot open AI cache file (%s): %s", $self->{cache_file},$!);
  } else {
    for ($!=0; defined($_=<CACHE>); $!=0) {
      my($k,$v) = split(/\t/, $_);
      next unless (defined $k && defined $v);
      $self->{cache}->{$k} = $v;
    }
    defined $_ || $!==0  or
      $!==EBADF ? dbg("AIcache: error reading from AI cache file: $!")
                : warn "error reading from AI cache file: $!";
    close CACHE
      or die "error closing AI cache file (".$self->{cache_file}."): $!";
  }

  bless($self,$class);
  $self;
}

sub count {
  my ($self) = @_;
  return keys %{$self->{cache}};
}

sub check {
  my ($self, $name) = @_;

  return $self->{cache} unless $name;

  # for dir collections: just use the info on a file, if an entry
  # exists for that file.  it's very unlikely that a file will be
  # changed to contain a different Date header, and it's slow to check.
  # return if ($self->{type} eq 'dir' && (stat($name))[9] > $self->{cache_mtime});

  $name = $self->canon($name);
  return $self->{cache}->{$name};
}

sub update {
  my ($self, $name, $date) = @_;

  return unless $name;
  $name = $self->canon($name);

  # if information is different than cached version, set dirty and update
  if (!exists $self->{cache}->{$name} || $self->{cache}->{$name} != $date) {
    $self->{cache}->{$name} = $date;
    $self->{dirty} = 1;
  }
}

sub finish {
  my ($self) = @_;

  return unless $self->{dirty};

  # Cache is dirty, so write out new file

  # create enclosing dir tree, if required
  eval {
    mkpath(dirname($self->{cache_file}));
    1;
  } or do {
    my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
    warn "cannot mkpath for AI cache file ($self->{cache_file}): $eval_stat\n";
  };

  my $towrite = '';
  while(my($k,$v) = each %{$self->{cache}}) {
    $towrite .= "$k\t$v\n";
  }

  {
    # ignore signals while we're writing this file
    local $SIG{'INT'} = 'IGNORE';
    local $SIG{'TERM'} = 'IGNORE';

    if (!open(CACHE, ">".$self->{cache_file}))
    {
      warn "creating AI cache file failed (".$self->{cache_file}."): $!";
      # TODO: should we delete it/clean it up?
    }
    else {
      print CACHE $towrite
        or warn "error writing to AI cache file: $!";
      close CACHE
        or warn "error closing AI cache file (".$self->{cache_file}."): $!";
    }
  }

  return;
}

sub canon {
  my ($self, $name) = @_;

  if ($self->{type} eq 'dir') {
    # strip off dirs, just look at filename
    $name = (File::Spec->splitpath($name))[2];
  }
  else {
    # we may get in a "/path/mbox.offset", so trim to just offset as necessary
    $name =~ s/^.+\.(\d+)$/$1/;
  }
  return $name;
}

# ---------------------------------------------------------------------------

1;
__END__
