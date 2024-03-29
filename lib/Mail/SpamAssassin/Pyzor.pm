package Mail::SpamAssassin::Pyzor;

# Copyright 2018 cPanel, LLC.
# All rights reserved.
# http://cpanel.net
#
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
#

use strict;
use warnings;

our $VERSION = '0.06_01';

=encoding utf-8

=head1 NAME

Mail::SpamAssassin::Pyzor - Pyzor spam filtering in Perl

=head1 DESCRIPTION

This distribution contains Perl implementations of parts of
L<Pyzor|http://pyzor.org>, a tool for use in spam email filtering.
It is intended for use with L<Mail::SpamAssassin> but may be useful
in other contexts.

See the following modules for information on specific tools that
the distribution includes:

=over

=item * L<Mail::SpamAssassin::Pyzor::Client>

=item * L<Mail::SpamAssassin::Pyzor::Digest>

=back

=cut

1;
