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

MSExec - determine if the message includes a Microsoft executable file

=head1 SYNOPSIS

  loadplugin     Mail::SpamAssassin::Plugin::MSExec
  body           MICROSOFT_EXECUTABLE eval:check_microsoft_executable()

=head1 DESCRIPTION

This rule works by checking for 3 possibilities in the message in any
application/* or text/* part in the message:

=over 4

=item - in text parts, look for a uuencoded executable start string

=item - in application parts, look for filenames ending in an executable extension

=item - in application parts, look for a base64 encoded executable start string

=back

=cut

package Mail::SpamAssassin::Plugin::MSExec;

use Mail::SpamAssassin::Plugin;
use strict;
use warnings;
use bytes;

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->register_eval_rule ("check_microsoft_executable");

  return $self;
}

sub check_microsoft_executable {
  my ($self, $permsgstatus) = @_;

  foreach my $p ($permsgstatus->{msg}->find_parts(qr/^(application|text)\b/)) {
    my ($ctype, $boundary, $charset, $name) =
      Mail::SpamAssassin::Util::parse_content_type($p->get_header('content-type'));

    if (lc $ctype eq 'application/octet-stream') {
      $name ||= '';
      $name = lc $name;

      # file extension indicates an executable ...
      return 1 if ($name =~ /\.(?:ade|adp|asx|bas|bat|chm|cmd|com|cpl|crt|dll|exe|hlp|hta|inf|ins|isp|js|jse|lnk|mda|mdb|mde|mdt|mdw|mdz|msc|msi|msp|mst|nws|ops|pcd|pif|prf|reg|scf|scr\??|sct|shb|shs|shm|swf|url|vb|vbe|vbs|vbx|vxd|wsc|wsf|wsh)$/);

      # base64 attached executable ...
      my $cte = lc $p->get_header('content-transfer-encoding') || '';
      return 1 if ($cte =~ /base64/ && $p->raw()->[0] =~ /^TV[opqr].A..[AB].[AQgw][A-H].A/);
    }
    elsif ($ctype =~ /^text\b/i) {
      # uuencoded executable ...
      foreach (@{$p->raw()}) {
        return 1 if (/^M35[GHIJK].`..`..*````/);
      }
    }
  }
  return 0;
}

1;
