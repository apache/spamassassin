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

DecodeShortURLs - deprecated, merged into Mail::SpamAssassin::Plugin::Redirectors

=head1 SYNOPSIS

  loadplugin    Mail::SpamAssassin::Plugin::DecodeShortURLs

=head1 DESCRIPTION

B<This plugin is deprecated.> All of its functionality (the C<url_shortener*>
settings and the C<short_url*> eval rules) has been merged into
L<Mail::SpamAssassin::Plugin::Redirectors>, which also gained the ability to
follow a redirect chain that mixes shorteners and redirectors in either
order -- there is no functional difference between the two, both are just
a host whose HTTP response redirects elsewhere.

This module remains only as a compatibility shim so that existing
configuration files with C<loadplugin Mail::SpamAssassin::Plugin::DecodeShortURLs>
keep working unchanged. It loads C<Redirectors> and inherits all of its
behavior. New configurations should load
C<Mail::SpamAssassin::Plugin::Redirectors> directly instead.

=head1 ACKNOWLEDGEMENTS

Original DecodeShortURLs plugin was developed by Steve Freegard.

=cut

package Mail::SpamAssassin::Plugin::DecodeShortURLs;

use Mail::SpamAssassin::Plugin::Redirectors;
use strict;
use warnings;

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin::Redirectors);

# Published rulesets (e.g. rules/25_url_shortener.cf) probe for plugin
# features with "if can(Mail::SpamAssassin::Plugin::DecodeShortURLs::has_x)",
# which calls the fully-qualified sub directly rather than as a method,
# that bypasses @ISA, so a plain subclass wouldn't expose subs it merely
# inherits from Redirectors. Alias them into this package's symbol table
# so such checks keep working.
BEGIN {
  no strict 'refs';
  for my $sub (qw(
    has_short_url has_autoclean has_short_url_code has_user_agent
    has_custom_user_agent has_get has_clear has_timeout
    has_max_redirections has_short_url_redir
  )) {
    *{$sub} = \&{"Mail::SpamAssassin::Plugin::Redirectors::$sub"};
  }
}

sub new {
  my $class = shift;
  my $mailsaobject = shift;

  Mail::SpamAssassin::Logger::dbg(
    "DecodeShortURLs: this plugin is deprecated, its functionality has been ".
    "merged into Redirectors; please switch to ".
    "'loadplugin Mail::SpamAssassin::Plugin::Redirectors'"
  );

  return $class->SUPER::new($mailsaobject);
}

1;
