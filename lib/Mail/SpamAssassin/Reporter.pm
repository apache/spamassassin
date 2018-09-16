# Mail::SpamAssassin::Reporter - report a message as spam

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

package Mail::SpamAssassin::Reporter;

use strict;
use warnings;
# use bytes;
use re 'taint';
use Mail::SpamAssassin::Logger;

our @ISA = qw();

#Removed $VERSION per BUG 6422
#$VERSION = 'bogus';	# avoid CPAN.pm picking up razor ver

###########################################################################

sub new {
  my $class = shift;
  $class = ref($class) || $class;
  my ($main, $msg, $options) = @_;

  my $self = {
    'main'		=> $main,
    'msg'		=> $msg,
    'options'		=> $options,
    'conf'		=> $main->{conf},
  };

  bless($self, $class);
  my $permsgstatus =
        Mail::SpamAssassin::PerMsgStatus->new($self->{main}, $msg);
  $msg->extract_message_metadata ($permsgstatus);
  $permsgstatus->finish();
  $self;
}

###########################################################################

sub report {
  my ($self) = @_;
  $self->{report_return} = 0;
  $self->{report_available} = 0;

  my $text = $self->{main}->remove_spamassassin_markup($self->{msg});

  $self->{main}->call_plugins("plugin_report", { report => $self, text => \$text, msg => $self->{msg} });

  $self->delete_fulltext_tmpfile();

  if ($self->{report_available} == 0) {
    warn "reporter: no reporting methods available, so couldn't report\n";
  }

  return $self->{report_return};
}

###########################################################################

sub revoke {
  my ($self) = @_;
  $self->{revoke_return} = 0;
  $self->{revoke_available} = 0;

  my $text = $self->{main}->remove_spamassassin_markup($self->{msg});

  $self->{main}->call_plugins("plugin_revoke", { revoke => $self, text => \$text, msg => $self->{msg} });

  if ($self->{revoke_available} == 0) {
    warn "reporter: no revoke methods available, so couldn't revoke\n";
  }

  return $self->{revoke_return};
}

###########################################################################

sub create_fulltext_tmpfile {
  Mail::SpamAssassin::PerMsgStatus::create_fulltext_tmpfile(@_);
}
sub delete_fulltext_tmpfile {
  Mail::SpamAssassin::PerMsgStatus::delete_fulltext_tmpfile(@_);
}

sub enter_helper_run_mode {
  Mail::SpamAssassin::PerMsgStatus::enter_helper_run_mode(@_);
}
sub leave_helper_run_mode {
  Mail::SpamAssassin::PerMsgStatus::leave_helper_run_mode(@_);
}

1;
