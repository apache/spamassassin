=head1 NAME

Mail::SpamAssassin::Plugin::DomainKeys

=head1 SYNOPSIS

 loadplugin Mail::SpamAssassin::Plugin::DomainKeys [/path/to/DomainKeys.pm]

 full DOMAINKEY_DOMAIN eval:check_domainkeys_senderdomain()

=head1 DESCRIPTION

This is the DomainKeys plugin and it needs lots more documentation.

=cut
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

package Mail::SpamAssassin::Plugin::DomainKeys;

use Mail::SpamAssassin::Plugin;
use strict;
use warnings;
use bytes;

use Mail::DomainKeys::Message;
use Mail::DomainKeys::Policy;

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->register_eval_rule ("check_domainkeys_senderdomain");
  $self->register_eval_rule ("check_domainkeys_verified");
  $self->register_eval_rule ("check_domainkeys_notsignedok");
  $self->register_eval_rule ("check_domainkeys_testing");
  $self->register_eval_rule ("check_domainkeys_signall");

  return $self;
}


sub check_domainkeys_senderdomain {
  my ($self, $permsgstatus) = @_;

  $self->_check_domainkeys($permsgstatus) unless $permsgstatus->{domainkeys_checked};
  
  return $permsgstatus->{domainkeys_found};
}

sub check_domainkeys_verified {
  my ($self, $permsgstatus) = @_;

  $self->_check_domainkeys($permsgstatus) unless $permsgstatus->{domainkeys_checked};
  
  return $permsgstatus->{domainkeys_verified};
}

sub check_domainkeys_notsignedok {
  my ($self, $permsgstatus) = @_;

  $self->_check_domainkeys($permsgstatus) unless $permsgstatus->{domainkeys_checked};
  
  return $permsgstatus->{domainkeys_notsignedok};
}

sub check_domainkeys_testing {
  my ($self, $permsgstatus) = @_;

  $self->_check_domainkeys($permsgstatus) unless $permsgstatus->{domainkeys_checked};
  
  return $permsgstatus->{domainkeys_testing};
}

sub check_domainkeys_signall {
  my ($self, $permsgstatus) = @_;

  $self->_check_domainkeys($permsgstatus) unless $permsgstatus->{domainkeys_checked};
  
  return $permsgstatus->{domainkeys_signall};
}



sub _check_domainkeys {
  my ($self, $permsgstatus) = @_;

  my $header = $permsgstatus->{msg}->get_pristine_header();
  my $body = $permsgstatus->{msg}->get_body();

  my $message = Mail::DomainKeys::Message->load(HeadString => $header,
						 BodyReference => $body);

  return unless $message;

  $permsgstatus->{domainkeys_checked} = 1;

  # does a sender domain header exist?
  return unless $message->senderdomain();

  $permsgstatus->{domainkeys_found} = 1;

  # verified
  if ($message->signed() && $message->verify()) {
    $permsgstatus->{domainkeys_verified} = 1;
  }

  my $policy = Mail::DomainKeys::Policy->fetch(Policy => 'dns',
					       Domain => $message->senderdomain());

  return unless $policy;

  # not signed and domain doesn't sign all
  if ($policy->signsome() && !$message->signed()) {
    $permsgstatus->{domainkeys_notsignedok} = 1;
  }

  # domain or key testing
  if ($message->testing() || $policy->testing()) {
    $permsgstatus->{domainkeys_testing} = 1;
  }

  # does policy require all mail to be signed
  if ($policy->signall()) {
    $permsgstatus->{domainkeys_signall} = 1;
  }

  return;
}

1;
