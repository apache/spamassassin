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

package Mail::SpamAssassin::FuzzyHash;

use strict;
use warnings;

our $VERSION = '1.0';

=head1 NAME

Mail::SpamAssassin::FuzzyHash - Fuzzy-hash similarity detection for SpamAssassin

=head1 DESCRIPTION

This is the root namespace for fuzzy-hash algorithms used by SpamAssassin
to detect near-duplicate spam messages.

=head1 AVAILABLE MODULES

=over 4

=item L<Mail::SpamAssassin::FuzzyHash::ZOrder>

MinHash-based fuzzy similarity using exactly 4 DNS TXT lookups.
Detects texts with approximately 90% token overlap efficiently.

=item L<Mail::SpamAssassin::FuzzyHash::Util>

Shared utility functions used by fuzzy-hash implementations:
C<normalize_tokens()> and C<hamming_distance()>.

=back

=cut

1;
