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

Mail::SpamAssassin::Plugin - SpamAssassin plugin base class

=head1 SYNOPSIS

  package MyPlugin;

  use Mail::SpamAssassin::Plugin;
  use vars qw(@ISA);
  @ISA = qw(Mail::SpamAssassin::Plugin);

  sub new {
    my $class = shift;
    my $mailsaobject = shift;
    
    # the usual perlobj boilerplate to create a subclass object
    $class = ref($class) || $class;
    my $self = $class->SUPER::new($mailsaobject);
    bless ($self, $class);
   
    # then register an eval rule
    $self->register_eval_rule ("check_for_foo");

    # and return the new plugin object
    return $self;
  }

  ...methods...

  1;

=head1 DESCRIPTION

This is the base class for SpamAssassin plugins; all plugins must be objects
that implement this class.

This class provides no-op stub methods for all the callbacks that a plugin
can receive.  It is expected that your plugin will override one or more
of these stubs to perform its actions.

SpamAssassin implements a plugin chain; each callback event is passed to each
of the registered plugin objects in turn.  Any plugin can call
C<$plugin->inhibit_further_callbacks()> to block delivery of that event to
later plugins in the chain.  This is useful if the plugin has handled the
event, and there will be no need for later plugins to handle it as well.

If you're looking to write a simple eval rule, skip straight to 
C<register_eval_rule()>, below.

=head1 INTERFACE

In all the plugin APIs below, C<options> refers to a reference to a hash
containing name-value pairs.   This is used to ensure future-compatibility, in
that we can add new options in future without affecting objects built to an
earlier version of the API.

For example, here would be how to print out the C<line> item in a
C<parse_config()> method:

  sub parse_config {
    my ($self, $opts) = @_;
    print "MyPlugin: parse_config got ".$opts->{line}."\n";
  }

=head1 METHODS

The following methods can be overridden by subclasses to handle events
that SpamAssassin will call back to:

=over 4

=cut

package Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin;

use strict;
use bytes;

use vars qw{
  @ISA $VERSION
};

@ISA = qw();
$VERSION = 'bogus';

###########################################################################

=item $plugin = MyPluginClass->new ($mailsaobject)

Constructor.  Plugins that need to register themselves will need to
define their own; the default super-class constructor will work fine
for plugins that just override a method.

Note that subclasses must provide the C<$mailsaobject> to the
superclass constructor, like so:

  my $self = $class->SUPER::new($mailsaobject);

=cut

sub new {
  my $class = shift;
  my $mailsaobject = shift;
  $class = ref($class) || $class;

  if (!defined $mailsaobject) {
    die "plugin: usage: Mail::SpamAssassin::Plugin::new(class,mailsaobject)";
  }

  my $self = {
    main => $mailsaobject,
    _inhibit_further_callbacks => 0
  };
  bless ($self, $class);
  $self;
}

# ---------------------------------------------------------------------------
# now list the supported methods we will call into.  NOTE: we don't have
# to implement them here, since the plugin can use "can()" to introspect
# the object and determine if it's capable of calling the method anyway.
# Nifty!

=item $plugin->parse_config ( { options ... } )

Parse a configuration line that hasn't already been handled.  C<options>
is a reference to a hash containing these options:

=over 4

=item line

The line of configuration text to parse.   This has leading and trailing
whitespace, and comments, removed.

=item user_config

A boolean: C<1> if reading a user's configuration, C<0> if reading the
system-wide configuration files.

=back

If the configuration line was a setting that is handled by this plugin, the
method implementation should call C<$plugin->inhibit_further_callbacks()> and
return C<1>.

If the setting is not handled by this plugin, the method should return C<0> so
that a later plugin may handle it, or so that SpamAssassin can output a warning
message to the user if no plugin understands it.

Note that it is suggested that configuration be stored on the
C<Mail::SpamAssassin::Conf> object in use, instead of the plugin object itself.
That can be found as C<$plugin->{main}->{conf}>.

=item $plugin->signal_user_changed ( { options ... } )

Signals that the current user has changed for a new one.

=over 4

=item username

The new user's username.

=item user_dir

The new user's storage directory.

=back

=item $plugin->check_start ( { options ... } )

Signals that a message check operation is starting.

=over 4

=item permsgstatus

The C<Mail::SpamAssassin::PerMsgStatus> context object for this scan.

=back

=item $plugin->extract_metadata ( { options ... } )

Signals that a message is being mined for metadata.  Some plugins may wish
to add their own metadata as well.

=over 4

=item msg

The C<Mail::SpamAssassin::Message> object for this message.

=back

=item $plugin->parsed_metadata ( { options ... } )

Signals that a message's metadata has been parsed, and can now be
accessed by the plugin.

=over 4

=item permsgstatus

The C<Mail::SpamAssassin::PerMsgStatus> context object for this scan.  (Note
that the message being scanned is accessible through the
C<$permsgstatus->get_message()> API.)

=back

=item $plugin->check_tick ( { options ... } )

Called periodically during a message check operation.  A callback set for
this method is a good place to run through an event loop dealing with
network events triggered in a C<parse_metadata> method, for example.

=over 4

=item permsgstatus

The C<Mail::SpamAssassin::PerMsgStatus> context object for this scan.

=back

=item $plugin->check_post_dnsbl ( { options ... } )

Called after the DNSBL results have been harvested.  This is a good
place to harvest your own asynchronously-started network lookups.

=over 4

=item permsgstatus

The C<Mail::SpamAssassin::PerMsgStatus> context object for this scan.

=back

=item $plugin->check_end ( { options ... } )

Signals that a message check operation has just finished, and the
results are about to be returned to the caller.

=over 4

=item permsgstatus

The C<Mail::SpamAssassin::PerMsgStatus> context object for this scan.
The current score, names of rules that hit, etc. can be retrieved
using the APIs on this object.

=back

=item $plugin->autolearn ( { options ... } )

Signals that a message is about to be auto-learned as either ham or spam.

=over 4

=item permsgstatus

The C<Mail::SpamAssassin::PerMsgStatus> context object for this scan.

=item isspam

C<1> if the message is spam, C<0> if ham.

=back

=item $plugin->per_msg_finish ( { options ... } )

Signals that a C<Mail::SpamAssassin::PerMsgStatus> object is being
destroyed, and any per-scan context held on that object by this
plugin should be destroyed as well.

=over 4

=item permsgstatus

The C<Mail::SpamAssassin::PerMsgStatus> context object for this scan.

=back

=item $plugin->finish ()

Called when the C<Mail::SpamAssassin> object is destroyed.

=back

=head1 HELPER APIS

These methods provide an API for plugins to register themselves
to receive specific events, or control the callback chain behaviour.

=over 4

=item $plugin->register_eval_rule ($nameofevalsub)

Plugins that implement an eval test will need to call this, so that
SpamAssassin calls into the object when that eval test is encountered.

For example,

  $plugin->register_eval_rule ('check_for_foo')

will cause C<$plugin->check_for_foo()> to be called for this
SpamAssassin rule:

  header   FOO_RULE	eval:check_for_foo()

Note that eval rules are passed the following arguments:

=over 4

=item The plugin object itself

=item The C<Mail::SpamAssassin::PerMsgStatus> object calling the rule

=item any and all arguments specified in the configuration file

=back

In other words, the eval test method should look something like this:

  sub check_for_foo {
    my ($self, $permsgstatus, ...arguments...) = @_;
    ...code returning 0 or 1
  }

Note that the headers can be accessed using the C<get()> method on the
C<Mail::SpamAssassin::PerMsgStatus> object, and the body by
C<get_decoded_stripped_body_text_array()> and other similar methods.
Similarly, the C<Mail::SpamAssassin::Conf> object holding the current
configuration may be accessed through C<$permsgstatus->{main}->{conf}>.

The eval rule should return C<1> for a hit, or C<0> if the rule
is not hit.

State for a single message being scanned should be stored on the C<$checker>
object, not on the C<$self> object, since C<$self> persists between scan
operations.

=cut

sub register_eval_rule {
  my ($self, $nameofsub) = @_;
  $self->{main}->{conf}->register_eval_rule ($self, $nameofsub);
}

=item $plugin->inhibit_further_callbacks()

Tells the plugin handler to inhibit calling into other plugins in the plugin
chain for the current callback.  Frequently used when parsing configuration
settings using C<parse_config()>.

=cut

sub inhibit_further_callbacks {
  my ($self) = @_;
  $self->{_inhibit_further_callbacks} = 1;
}

=item dbg ($message)

Output a debugging message C<$message>, if the SpamAssassin object is running
with debugging turned on.

=cut

sub dbg { Mail::SpamAssassin::dbg (@_); }

1;

=back

=head1 SEE ALSO

C<Mail::SpamAssassin>

C<Mail::SpamAssassin::PerMsgStatus>

http://bugzilla.spamassassin.org/show_bug.cgi?id=2163

=cut
