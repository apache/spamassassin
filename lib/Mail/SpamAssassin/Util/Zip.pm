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

Mail::SpamAssassin::Util::Zip - read zip archives within a size limit

=head1 SYNOPSIS

  use Mail::SpamAssassin::Util::Zip;

  my $zip = Mail::SpamAssassin::Util::Zip::open_zip(\$data) or return;
  foreach my $member ($zip->members()) {
    my ($content, $produced) =
      Mail::SpamAssassin::Util::Zip::member_contents($member, $limit);
  }

=head1 DESCRIPTION

Reads zip archives held in memory with L<Archive::Zip>, uncompressing members
in small steps so that the output never goes far past the caller's limit.  The
sizes declared in an archive are not trusted.

Several zip archives joined end to end, a known way of hiding files from zip
readers that show only the first or only the last, are all read.

=cut

package Mail::SpamAssassin::Util::Zip;

use strict;
use warnings;
use re 'taint';

use Mail::SpamAssassin::Logger;

use constant HAS_ARCHIVE_ZIP => eval { require Archive::Zip; 1 };

# 1 KB of deflated input uncompresses to at most about 1 MB
use constant CHUNK_SIZE => 1024;

# joined archives tried from the start of the data, besides the last one
use constant MAX_ARCHIVES => 4;

=over 4

=item open_zip(\$data)

Returns an object for the zip archives in C<$data>, or undef if Archive::Zip is
not installed or no zip archive can be read from the data.  Of joined archives,
up to 4 are read from the start of the data, and the last one is always read.
C<$data> must not change while the object is in use.

The object's C<members>, C<memberNamed> and C<membersMatching> methods work as
those of L<Archive::Zip> do, over all the archives read, in order.

=cut

sub open_zip {
  my ($dataref) = @_;
  return unless HAS_ARCHIVE_ZIP;

  # an archive ends with its end of central directory record: a signature,
  # disk numbers, entry counts, the central directory's size and offset, and a
  # comment.  Read the data up to each such record that declares entries and
  # follows a central directory, leaving out the comment, which may itself
  # contain a signature, and skipping records inside an archive already read.
  my @archives;
  my ($start, $pos, $tries) = (0, 0, 0);
  while ($tries < MAX_ARCHIVES
         && ($pos = index($$dataref, "PK\x05\x06", $pos)) >= 0) {
    my $sig = $pos;
    $pos += 4;
    next if $sig < $start || $sig + 22 > length($$dataref);
    my ($entries, $cd_size) = unpack('vV', substr($$dataref, $sig + 10, 6));
    next unless $entries && $cd_size <= $sig
                && substr($$dataref, $sig - $cd_size, 4) eq "PK\x01\x02";
    $tries++;
    my $prefix = substr($$dataref, 0, $sig + 20) . "\0\0";
    my $zip = _read_zip(\$prefix) or next;
    push @archives, $zip;
    $start = $sig + 22 + unpack('v', substr($$dataref, $sig + 20, 2));
  }

  # the last archive, read from the whole data as Archive::Zip finds it
  if (rindex($$dataref, "PK\x05\x06") >= $start) {
    my $zip = _read_zip($dataref);
    push @archives, $zip if $zip;
  }

  return unless @archives;
  return bless { archives => \@archives }, __PACKAGE__;
}

sub members {
  my ($self) = @_;
  return map { $_->members() } @{$self->{archives}};
}

sub memberNamed {
  my ($self, $name) = @_;
  foreach my $zip (@{$self->{archives}}) {
    my $member = $zip->memberNamed($name);
    return $member if $member;
  }
  return;
}

sub membersMatching {
  my ($self, @args) = @_;
  return map { $_->membersMatching(@args) } @{$self->{archives}};
}

sub _read_zip {
  my ($dataref) = @_;
  # read the archive straight from the in-memory scalar: an in-core filehandle
  # (open ..., \$scalar) does what IO::String did, without the CPAN dependency.
  open(my $fh, '<', $dataref) or return;
  binmode $fh;
  my $old_handler = Archive::Zip::setErrorHandler(\&_zip_error);
  my $zip = Archive::Zip->new();
  my $status = $zip->readFromFileHandle($fh);
  Archive::Zip::setErrorHandler($old_handler);
  return unless $status == Archive::Zip::AZ_OK();
  return $zip;
}

=item member_contents($member, $limit)

Uncompresses the L<Archive::Zip::Member> C<$member>.  Returns the data, or undef
if the member is encrypted, cannot be read, or uncompresses to more than
C<$limit> bytes; and as a second value the number of bytes uncompressed, which
callers should count against their limits whether or not the data is returned.

=back

=cut

sub member_contents {
  my ($member, $limit) = @_;
  return (undef, 0) if $member->isEncrypted();
  return (undef, 0) if $member->uncompressedSize() > $limit;

  my $old_handler = Archive::Zip::setErrorHandler(\&_zip_error);
  my $method = $member->desiredCompressionMethod(
                 Archive::Zip::COMPRESSION_STORED());
  my $status = $member->rewindData();
  my $data = '';
  while ($status == Archive::Zip::AZ_OK()) {
    (my $chunk, $status) = $member->readChunk(CHUNK_SIZE);
    $data .= $$chunk if $status == Archive::Zip::AZ_OK()
                     || $status == Archive::Zip::AZ_STREAM_END();
    last if length($data) > $limit;
  }
  $member->endRead();
  $member->desiredCompressionMethod($method);
  Archive::Zip::setErrorHandler($old_handler);

  my $produced = length($data);
  return (undef, $produced) if $produced > $limit
                            || $status != Archive::Zip::AZ_STREAM_END();
  return ($data, $produced);
}

sub _zip_error {
  my ($msg) = @_;
  chomp $msg;
  dbg("zip: $msg");
}

1;
