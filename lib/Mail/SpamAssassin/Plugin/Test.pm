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

Test - test plugin

=head1 SYNOPSIS

  loadplugin     Mail::SpamAssassin::Plugin::Test
  header         MY_TEST_PLUGIN eval:check_test_plugin()

=head1 DESCRIPTION

To try this plugin, write the above two lines in the synopsis to
C</etc/mail/spamassassin/plugintest.cf>.

=cut

package Mail::SpamAssassin::Plugin::Test;

use Mail::SpamAssassin::Plugin;
use strict;
use warnings;
# use bytes;
use re 'taint';

our @ISA = qw(Mail::SpamAssassin::Plugin);

# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  # the important bit!
  $self->register_eval_rule ("check_test_plugin");

  print "registered Mail::SpamAssassin::Plugin::Test: $self\n"
    or die "Error writing: $!";
  return $self;
}

# and the eval rule itself
sub check_test_plugin {
  my ($self, $permsgstatus) = @_;
  print "Mail::SpamAssassin::Plugin::Test eval test called: $self\n"
    or die "Error writing: $!";
  # ... hard work goes here...
  return 1;
}

sub test_feature_xxxx_false { undef }
sub test_feature_xxxx_true  { 1 }

1;
