# Helper code to debug dependencies and their versions.

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

package Mail::SpamAssassin::Util::DependencyInfo;

use strict;
use warnings;
use bytes;

use vars qw (
  @MODULES
);

@MODULES = qw(
        Net::DNS Razor2::Client::Agent MIME::Base64
        IO::Socket::UNIX DB_File Digest::SHA1
        DBI URI Net::LDAP Storable
);

###########################################################################

=item $f->debug_diagnostics ()

Output some diagnostic information, useful for debugging SpamAssassin
problems.

=cut

sub debug_diagnostics {
  my $out = "diag: perl platform: $] $^O\n";

  foreach my $module (sort @MODULES) {
    my $modver;
    if (eval ' require '.$module.'; $modver = $'.$module.'::VERSION; 1;')
    {
      $modver ||= '(undef)';
      $out .= "module installed: $module, version $modver\n";
    } else {
      $out .= "module not installed: $module ('require' failed)\n";
    }
  }
  return $out;
}

1;
