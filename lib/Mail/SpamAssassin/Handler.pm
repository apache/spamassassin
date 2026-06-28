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

Mail::SpamAssassin::Handler - superclass for MIME-part handlers

=head1 SYNOPSIS

  package MyHandler;
  use Mail::SpamAssassin::Handler;
  our @ISA = qw(Mail::SpamAssassin::Handler);

  sub new {
    my ($class, $mailsaobject) = @_;
    $class = ref($class) || $class;
    my $self = $class->SUPER::new($mailsaobject);
    bless ($self, $class);
    $self->register_handler('image/jpeg', 'handle_jpeg');
    return $self;
  }

  sub handle_jpeg {
    my ($self, $node, $permsgstatus) = @_;
    # ... analyse the part, optionally return synthetic child parts ...
    return [];
  }

=head1 DESCRIPTION

A B<handler> is a plugin that processes individual MIME parts: it registers
itself for one or more content types with L<register_handler|/item_register_handler>
and is invoked once per matching part during message metadata extraction.

C<Mail::SpamAssassin::Handler> is a thin subclass of
L<Mail::SpamAssassin::Plugin>.  Handlers are loaded, configured and dispatched
through the same machinery as plugins; inheriting from this class instead of
from C<Mail::SpamAssassin::Plugin> gives handlers a distinct identity (so they
can be told apart with C<< $obj->isa('Mail::SpamAssassin::Handler') >>) and a
place for handler-specific behaviour to live in future.  Handlers are loaded
with the C<loadhandler> / C<tryhandler> configuration directives, and a block of
configuration can be made conditional on a handler with C<ifhandler>.

Everything in L<Mail::SpamAssassin::Plugin> is available to handlers; only the
handler-specific method below is added here.

=cut

package Mail::SpamAssassin::Handler;

use strict;
use warnings;
use re 'taint';

use Mail::SpamAssassin::Plugin;

our @ISA = qw(Mail::SpamAssassin::Plugin);

###########################################################################

=over 4

=item $handler-E<gt>register_handler ($mime_pattern, $nameofsub)

Register one of this handler's methods as the MIME-part handler for a
content-type pattern.  C<$mime_pattern> is an exact type (C<image/jpeg>) or a
major-type glob (C<image/*>); the most specific match wins.  C<$nameofsub> is
the name of a method on this handler that will be called as
C<< $handler->$nameofsub($node, $permsgstatus) >> for each matching MIME part,
during message metadata extraction (before body rules run and before the URI
list is frozen).

The method may inject extracted text into the part with
C<< $node->set_rendered($text, $type) >>, accumulate per-message findings on
C<$permsgstatus>, and return an arrayref of synthetic child-part specs
(C<< { type => ..., data => $bytes, name => ... } >>) which are dispatched
recursively -- or C<undef>/C<[]> for none.

=cut

sub register_handler {
  my ($self, $mime_pattern, $nameofsub) = @_;
  $self->{main}->{conf}->register_handler ($self, $mime_pattern, $nameofsub);
}

=back

=head1 SEE ALSO

L<Mail::SpamAssassin::Plugin>

=cut

1;
