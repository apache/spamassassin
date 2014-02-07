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

Mail::SpamAssassin::Plugin - SpamAssassin plugin base class

=head1 SYNOPSIS

=head2 SpamAssassin configuration:

  loadplugin MyPlugin /path/to/myplugin.pm

=head2 Perl code:

  package MyPlugin;

  use Mail::SpamAssassin::Plugin;
  our @ISA = qw(Mail::SpamAssassin::Plugin);

  sub new {
    my ($class, $mailsa) = @_;
    
    # the usual perlobj boilerplate to create a subclass object
    $class = ref($class) || $class;
    my $self = $class->SUPER::new($mailsa);
    bless ($self, $class);
   
    # then register an eval rule, if desired...
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
C<$self-E<gt>inhibit_further_callbacks()> to block delivery of that event to
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

The following methods can be overridden by subclasses to handle events.

=over 4

=cut

package Mail::SpamAssassin::Plugin;

use Mail::SpamAssassin;
use Mail::SpamAssassin::Logger;

use strict;
use warnings;
use bytes;
use re 'taint';

use vars qw{
  @ISA $VERSION
};

@ISA =                  qw();
#Removed $VERSION per BUG 6422
#$VERSION =              'bogus';

###########################################################################

=item $plugin = MyPluginClass->new ($mailsaobject)

Constructor.  Plugins that need to register themselves will need to
define their own; the default super-class constructor will work fine
for plugins that just override a method.

Note that subclasses must provide the C<$mailsaobject> to the
superclass constructor, like so:

  my $self = $class->SUPER::new($mailsaobject);

Lifecycle note: plugins that will need to store per-scan state should not store
that on the Plugin object; instead this should be stored on the PerMsgStatus
object, see C<check_start()> below.  It is also likewise recommended that
configuration settings be stored on the Conf object; see C<parse_config()>.

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

=item key

The configuration key; ie. the first "word" on the line.

=item value

The configuration value; everything after the first "word" and
any whitespace after that.

=item conf

The C<Mail::SpamAssassin::Conf> object on which the configuration
data should be stored.

=item user_config

A boolean: C<1> if reading a user's configuration, C<0> if reading the
system-wide configuration files.

=back

If the configuration line was a setting that is handled by this plugin, the
method implementation should call C<$self-E<gt>inhibit_further_callbacks()>.

If the setting is not handled by this plugin, the method should return C<0> so
that a later plugin may handle it, or so that SpamAssassin can output a warning
message to the user if no plugin understands it.

Lifecycle note: it is suggested that configuration be stored on the
C<Mail::SpamAssassin::Conf> object in use, instead of the plugin object itself.
That can be found as C<$plugin-E<gt>{main}-E<gt>{conf}>, or as "conf" in the
C<$options> hash reference above.   By storing it on C<conf>, this allows
per-user and system-wide configuration precedence to be dealt with correctly.

=item $plugin->finish_parsing_start ( { options ... } )

Signals that the system-wide configuration has been completely read,
but internal data structures are not yet created. It is possible to
use this hook to dynamically change the configuration already read in
or add new config options.

C<options> is a reference to a hash containing these options:

=over 4

=item conf

The C<Mail::SpamAssassin::Conf> object on which the configuration
data should be stored.

=back

Note: there are no guarantees that the internal data structures of
SpamAssassin will not change from release to release.  In particular to
this plugin hook, if you modify the rules data structures in a
third-party plugin, all bets are off until such time that an API is
present for modifying that configuration data.

=item $plugin->finish_parsing_end ( { options ... } )

Signals that the system-wide configuration parsing has just finished, and
SpamAssassin is nearly ready to check messages.

C<options> is a reference to a hash containing these options:

=over 4

=item conf

The C<Mail::SpamAssassin::Conf> object on which the configuration
data should be stored.

=back

Note: there are no guarantees that the internal data structures of
SpamAssassin will not change from release to release.  In particular to
this plugin hook, if you modify the rules data structures in a
third-party plugin, all bets are off until such time that an API is
present for modifying that configuration data.

=item $plugin->user_conf_parsing_start ( { options ... } )

Signals that the per-user configuration has been completely read, but
not converted to internal data structures. It is possible to use this
hook to dynamically change the configuration already read in or add
new config options.

If C<allow_user_rules> is enabled in the configuration, it is possible
that additional rules have been added since the C<finish_parsing_start>
plugin hook invocation was called.

=over 4

=item conf

The C<Mail::SpamAssassin::Conf> object on which the configuration
data should be stored.

=back

Note: there are no guarantees that the internal data structures of
SpamAssassin will not change from release to release.  In particular to
this plugin hook, if you modify the rules data structures in a
third-party plugin, all bets are off until such time that an API is
present for modifying that configuration data.

=item $plugin->user_conf_parsing_end ( { options ... } )

Signals that the per-user configuration parsing has just finished, and
SpamAssassin is nearly ready to check messages.   If C<allow_user_rules> is
enabled in the configuration, it is possible that additional rules have been
added since the C<finish_parsing_end> plugin hook invocation was called.

C<options> is a reference to a hash containing these options:

=over 4

=item conf

The C<Mail::SpamAssassin::Conf> object on which the configuration
data should be stored.

=back

Note: there are no guarantees that the internal data structures of
SpamAssassin will not change from release to release.  In particular to
this plugin hook, if you modify the rules data structures in a
third-party plugin, all bets are off until such time that an API is
present for modifying that configuration data.

=item $plugin->signal_user_changed ( { options ... } )

Signals that the current user has changed for a new one.

=over 4

=item username

The new user's username.

=item user_dir

The new user's home directory. (equivalent to C<~>.)

=item userstate_dir

The new user's storage directory. (equivalent to C<~/.spamassassin>.)

=back

=item $plugin->services_authorized_for_username ( { options ... } )

Validates that a given username is authorized to use certain services.

In order to authorize a user, the plugin should first check that it can
handle any of the services passed into the method and then set the value
for each allowed service to true (or any non-negative value).

The current supported services are: bayessql

=over 4

=item username

A username

=item services

Reference to a hash containing the services you want to check.

{

  'bayessql' => 0

}

=item conf

The C<Mail::SpamAssassin::Conf> object on which the configuration
data should be stored.

=back

=item $plugin->compile_now_start ( { options ... } )

This is called at the beginning of Mail::SpamAssassin::compile_now() so
plugins can do any necessary initialization for multi-process
SpamAssassin (such as spamd or mass-check -j).

=over 4

=item use_user_prefs

The value of $use_user_prefs option in compile_now().

=item keep_userstate

The value of $keep_userstate option in compile_now().

=back

=item $plugin->compile_now_finish ( { options ... } )

This is called at the end of Mail::SpamAssassin::compile_now() so
plugins can do any necessary initialization for multi-process
SpamAssassin (such as spamd or mass-check -j).

=over 4

=item use_user_prefs

The value of $use_user_prefs option in compile_now().

=item keep_userstate

The value of $keep_userstate option in compile_now().

=back

=item $plugin->check_start ( { options ... } )

Signals that a message check operation is starting.

=over 4

=item permsgstatus

The C<Mail::SpamAssassin::PerMsgStatus> context object for this scan.

Lifecycle note: it is recommended that rules that need to track test state on a
per-scan basis should store that state on this object, not on the plugin object
itself, since the plugin object will be shared between all active scanners.

The message being scanned is accessible through the
C<$permsgstatus-E<gt>get_message()> API; there are a number of other public
APIs on that object, too.  See C<Mail::SpamAssassin::PerMsgStatus> perldoc.

=back

=item $plugin->check_main ( { options ... } )

Signals that a message should be checked.  Note that implementations of
this hook should return C<1>.

=over 4

=item permsgstatus

The C<Mail::SpamAssassin::PerMsgStatus> context object for this scan.

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

=item $plugin->check_post_learn ( { options ... } )

Called after auto-learning may (or may not) have taken place.  If you
wish to perform additional learning, whether or not auto-learning
happens, this is the place to do it.

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
using the public APIs on this object.

=back

=item $plugin->finish_tests ( { options ... } )

Called via C<Mail::SpamAssassin::finish>.  This should clear up any tests that
a plugin has added to the namespace.

In certain circumstances, plugins may find it useful to compile
perl functions from the ruleset, on the fly.  It is important to
remove these once the C<Mail::SpamAssassin> object is deleted,
however, and this API allows this.

Each plugin is responsible for its own generated perl functions.

=over 4

=item conf

The C<Mail::SpamAssassin::Conf> object on which the configuration
data should be stored.

=back

See also the C<register_generated_rule_method> helper API, below.

=item $plugin->extract_metadata ( { options ... } )

Signals that a message is being mined for metadata.  Some plugins may wish
to add their own metadata as well.

=over 4

=item msg

The C<Mail::SpamAssassin::Message> object for this message.

=item permsgstatus

The C<Mail::SpamAssassin::PerMsgStatus> context object for this scan.

=back

=item $plugin->parsed_metadata ( { options ... } )

Signals that a message's metadata has been parsed, and can now be
accessed by the plugin.

=over 4

=item permsgstatus

The C<Mail::SpamAssassin::PerMsgStatus> context object for this scan.

=back

=item $plugin->start_rules ( { options ... } )

Called before testing a set of rules of a given type and priority.

=over 4

=item permsgstatus

The C<Mail::SpamAssassin::PerMsgStatus> context object for this scan.

=item ruletype

The type of the rules about to be performed.

=item priority

The priority level of the rules about to be performed.

=back

=item $plugin->hit_rule ( { options ... } )

Called when a rule fires.

=over 4

=item permsgstatus

The C<Mail::SpamAssassin::PerMsgStatus> context object for this scan.

=item ruletype

The type of the rule that fired.

=item rulename

The name of the rule that fired.

=item score

The rule's score in the active scoreset.

=back

=item $plugin->ran_rule ( { options ... } )

Called after a rule has been tested, whether or not it fired.  When the
rule fires, the hit_rule callback is always called before this.

=over 4

=item permsgstatus

The C<Mail::SpamAssassin::PerMsgStatus> context object for this scan.

=item ruletype

The type of the rule that was tested.

=item rulename

The name of the rule that was tested.

=back

=item $plugin->autolearn_discriminator ( { options ... } )

Control whether a just-scanned message should be learned as either
spam or ham.   This method should return one of C<1> to learn
the message as spam, C<0> to learn as ham, or C<undef> to not
learn from the message at all.

=over 4

=item permsgstatus

The C<Mail::SpamAssassin::PerMsgStatus> context object for this scan.

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

Normally, any member variables on the C<PerMsgStatus> object will be cleaned up
automatically -- but if your plugin has made a circular reference on that
object, this is the place to break them so that garbage collection can operate
correctly.

=over 4

=item permsgstatus

The C<Mail::SpamAssassin::PerMsgStatus> context object for this scan.

=back


=item $plugin->have_shortcircuited ( { options ... } )

Has the current scan operation 'short-circuited'?  In other words, can
further scanning be skipped, since the message is already definitively
classified as either spam or ham?

Plugins should return C<0> to indicate that scanning should continue,
or C<1> to indicate that short-circuiting has taken effect.

=over 4

=item permsgstatus

The C<Mail::SpamAssassin::PerMsgStatus> context object for this scan.

=back

=item $plugin->bayes_learn ( { options ... } )

Called at the end of a bayes learn operation.

This phase is the best place to map the raw (original) token value
to the SHA1 hashed value.

=over 4

=item toksref

Reference to hash returned by call to tokenize.  The hash takes the
format of:

  {
    'SHA1 Hash Value' => 'raw (original) value',
    ...
  }

NOTE: This data structure has changed since it was originally introduced
in version 3.0.0.  The values are no longer perl anonymous hashes, they
are a single string containing the raw token value.  You can test for
backward compatibility by checking to see if the value for a key is a
reference to a perl HASH, for instance:

if (ref($toksref->{$sometokenkey}) eq 'HASH') {...

If it is, then you are using the old interface, otherwise you are using
the current interface.

=item isspam

Boolean value stating what flavor of message the tokens represent, if
true then message was specified as spam, false is nonspam.  Note, when
function is scan then isspam value is not valid.

=item msgid

Generated message id of the message just learned.

=item msgatime

Received date of the current message or current time if received date
could not be determined.  In addition, if the receive date is more than
24 hrs into the future it will be reset to current datetime.

=back

=item $plugin->bayes_forget ( { options ... } )

Called at the end of a bayes forget operation.

=over 4

=item toksref

Reference to hash returned by call to tokenize.  See bayes_learn
documentation for additional information on the format.

=item isspam

Boolean value stating what flavor of message the tokens represent, if
true then message was specified as spam, false is nonspam.  Note, when
function is scan then isspam value is not valid.

=item msgid

Generated message id of the message just forgotten.

=back

=item $plugin->bayes_scan ( { options ... } )

Called at the end of a bayes scan operation.  NOTE: Will not be
called in case of error or if the message is otherwise skipped.

=over 4

=item toksref

Reference to hash returned by call to tokenize.  See bayes_learn
documentation for additional information on the format.

=item probsref

Reference to hash of calculated probabilities for tokens found in
the database.

  {
    'SHA1 Hash Value' => {
            'prob' => 'calculated probability',
            'spam_count' => 'Total number of spam msgs w/ token',
            'ham_count' => 'Total number of ham msgs w/ token',
            'atime' => 'Atime value for token in database'
          }
  }

=item score

Score calculated for this particular message.

=item msgatime

Calculated atime of the message just learned, note it may have been adjusted
if it was determined to be too far into the future.

=item significant_tokens

Array ref of the tokens found to be significant in determining the score for
this message.

=back

=item $plugin->plugin_report ( { options ... } )

Called if the message is to be reported as spam.  If the reporting system is
available, the variable C<$options-E<gt>{report}-E<gt>report_available}> should
be set to C<1>; if the reporting system successfully reported the message, the
variable C<$options-E<gt>{report}-E<gt>report_return}> should be set to C<1>.

=over 4

=item report

Reference to the Reporter object (C<$options-E<gt>{report}> in the
paragraph above.)

=item text

Reference to a markup removed copy of the message in scalar string format.

=item msg

Reference to the original message object.

=back

=item $plugin->plugin_revoke ( { options ... } )

Called if the message is to be reported as ham (revokes a spam report). If the
reporting system is available, the variable
C<$options-E<gt>{revoke}-E<gt>revoke_available}> should be set to C<1>; if the
reporting system successfully revoked the message, the variable
C<$options-E<gt>{revoke}-E<gt>revoke_return}> should be set to C<1>.

=over 4

=item revoke

Reference to the Reporter object (C<$options-E<gt>{revoke}> in the
paragraph above.)

=item text

Reference to a markup removed copy of the message in scalar string format.

=item msg

Reference to the original message object.

=back

=item $plugin->whitelist_address( { options ... } )

Called when a request is made to add an address to a
persistent address list.

=over 4

=item address

Address you wish to add.

=item cli_p

Indicate if the call is being made from a command line interface.

=back

=item $plugin->blacklist_address( { options ... } )

Called when a request is made to add an address to a
persistent address list.

=over 4

=item address

Address you wish to add.

=item cli_p

Indicate if the call is being made from a command line interface.

=back

=item $plugin->remove_address( { options ... } )

Called when a request is made to remove an address to a
persistent address list.

=over 4

=item address

Address you wish to remove.

=item cli_p

Indicate if the call is being made from a command line interface.

=back

=item $plugin->spamd_child_init ()

Called in each new child process when it starts up under spamd.

=item $plugin->log_scan_result ( { options ... } )

Called when spamd has completed scanning a message.  Currently,
only spamd calls this API.

=over 4

=item result

The C<'result: ...'> line for this scan.  Format is as described
at B<http://wiki.apache.org/spamassassin/SpamdSyslogFormat>.

=back

=item $plugin->spamd_child_post_connection_close ()

Called when child returns from handling a connection.

If there was an accept failure, the child will die and this code will
not be called.

=item $plugin->finish ()

Called when the C<Mail::SpamAssassin> object is destroyed.

=cut

sub finish {
  my ($self) = @_;
  %{$self} = ();
}

=item $plugin->learner_new ()

Used to support human-trained probabilistic classifiers like the BAYES_* ruleset.
Called when a new C<Mail::SpamAssassin::Bayes> object has been created; typically
when a new user's scan is about to start.

=item $plugin->learn_message ()

Train the classifier with a training message.

=over 4

=item isspam

1 if the message is spam, 0 if it's non-spam.

=item msg

The message's C<Mail::SpamAssassin::Message> object.

=item id

An optional message-identification string, used internally to tag the message.
If it is C<undef>, one will be generated.  It should be unique to that message.

=back

=item $plugin->forget_message ()

Tell the classifier to 'forget' its training about a specific message.

=over 4

=item msg

The message's C<Mail::SpamAssassin::Message> object.

=item id

An optional message-identification string, used internally to tag the message.
If it is C<undef>, one will be generated.  It should be unique to that message.

=back

=item $plugin->learner_sync ()

Tell the classifier to 'sync' any pending changes against the current 
user's training database.  This is called by C<sa-learn --sync>.

If you do not need to implement these for your classifier, create an
implementation that just contains C<return 1>.

=item $plugin->learner_expire_old_training ()

Tell the classifier to perform infrequent, time-consuming cleanup of
the current user's training database.  This is called by C<sa-learn
--force-expire>.

If you do not need to implement these for your classifier, create an
implementation that just contains C<return 1>.

=item $plugin->learner_is_scan_available ()

Should return 1 if it is possible to use the current user's training data for
a message-scan operation, or 0 otherwise.

=item $plugin->learner_dump_database ()

Dump information about the current user's training data to C<stdout>.
This is called by C<sa-learn --dump>.

=over 4

=item magic

Set to 1 if "magic" name-value metadata should be dumped.

=item toks

Set to 1 if the database of tokens should be dumped.

=item regex

Either C<undef> to dump all tokens, or a value which specifies a regular expression
subset of the tokens to dump.

=back

=item $plugin->learner_close ()

Close any open databases.

=over 4

=item quiet

Set to 1 if warning messages should be suppressed.

=back

=back

=head1 HELPER APIS

These methods provide an API for plugins to register themselves
to receive specific events, or control the callback chain behaviour.

=over 4

=item $plugin->register_eval_rule ($nameofevalsub)

Plugins that implement an eval test will need to call this, so that
SpamAssassin calls into the object when that eval test is encountered.
See the B<REGISTERING EVAL RULES> section for full details.

=cut

sub register_eval_rule {
  my ($self, $nameofsub) = @_;
  $self->{main}->{conf}->register_eval_rule ($self, $nameofsub);
}

=item $plugin->register_generated_rule_method ($nameofsub)

In certain circumstances, plugins may find it useful to compile
perl functions from the ruleset, on the fly.  It is important to
remove these once the C<Mail::SpamAssassin> object is deleted,
however, and this API allows this.

Once the method C<$nameofsub> has been generated, call this API
with the name of the method (including full package scope).
This indicates that it's a temporary piece of generated code,
built from the SpamAssassin ruleset, and when 
C<Mail::SpamAssassin::finish()> is called, the method will
be destroyed.

This API was added in SpamAssassin 3.2.0.

=cut

sub register_generated_rule_method {
  my ($self, $nameofsub) = @_;
  push @Mail::SpamAssassin::PerMsgStatus::TEMPORARY_METHODS,
        $nameofsub;
}

=item $plugin->register_method_priority($methodname, $priority)

Indicate that the method named C<$methodname> on the current object
has a callback priority of C<$priority>.

This is used by the plugin handler to determine the relative order of
callbacks; plugins with lower-numbered priorities are called before plugins
with higher-numbered priorities.  Each method can have a different priority
value.  The default value is C<0>.  The ordering of callbacks to methods with
equal priority is undefined.

Typically, you only need to worry about this if you need to ensure your
plugin's method is called before another plugin's implementation of that
method.  It should be called from your plugin's constructor.

This API was added in SpamAssassin 3.2.0.

=cut

sub register_method_priority {
  my ($self, $methname, $pri) = @_;
  $self->{method_priority}->{$methname} = $pri;
}

=item $plugin->inhibit_further_callbacks()

Tells the plugin handler to inhibit calling into other plugins in the plugin
chain for the current callback.  Frequently used when parsing configuration
settings using C<parse_config()>.

=back

=cut

sub inhibit_further_callbacks {
  my ($self) = @_;
  $self->{_inhibit_further_callbacks} = 1;
}

1;
__END__

=head1 LOGGING

=over 4

=item Mail::SpamAssassin::Plugin::dbg($message)

Output a debugging message C<$message>, if the SpamAssassin object is running
with debugging turned on.

I<NOTE:> This function is not available in the package namespace
of general plugins and can't be called via $self->dbg().  If a
plugin wishes to output debug information, it should call
C<Mail::SpamAssassin::Plugin::dbg($msg)>.

=item Mail::SpamAssassin::Plugin::info($message)

Output an informational message C<$message>, if the SpamAssassin object
is running with informational messages turned on.

I<NOTE:> This function is not available in the package namespace
of general plugins and can't be called via $self->info().  If a
plugin wishes to output debug information, it should call
C<Mail::SpamAssassin::Plugin::info($msg)>.

In general, it is better for plugins to use the C<Mail::SpamAssassin::Logger>
module to import C<dbg> and C<info> directly, like so:

  use Mail::SpamAssassin::Logger;
  dbg("some message");
  info("some other message");

=back

=head1 REGISTERING EVAL RULES

Plugins that implement an eval test must register the methods that can be
called from rules in the configuration files, in the plugin class' constructor.

For example,

  $plugin->register_eval_rule ('check_for_foo')

will cause C<$plugin-E<gt>check_for_foo()> to be called for this
SpamAssassin rule:

  header   FOO_RULE	eval:check_for_foo()

Note that eval rules are passed the following arguments:

=over 4

=item - The plugin object itself

=item - The C<Mail::SpamAssassin::PerMsgStatus> object calling the rule

=item - standard arguments for the rule type in use

=item - any and all arguments as specified in the configuration file

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
configuration may be accessed through C<$permsgstatus-E<gt>{main}-E<gt>{conf}>.

The eval rule should return C<1> for a hit, or C<0> if the rule
is not hit.

State for a single message being scanned should be stored on the C<$permsgstatus>
object, not on the C<$self> object, since C<$self> persists between scan
operations.  See the 'lifecycle note' on the C<check_start()> method above.

=head1 STANDARD ARGUMENTS FOR RULE TYPES

Plugins will be called with the same arguments as a standard EvalTest.
Different rule types receive different information by default:

=over 4

=item - header tests: no extra arguments

=item - body tests: fully rendered message as array reference

=item - rawbody tests: fully decoded message as array reference

=item - full tests: pristine message as scalar reference

=back

The configuration file arguments will be passed in after the standard
arguments.

=head1 BACKWARD COMPATIBILITY

Note that if you write a plugin and need to determine if a particular
helper method is supported on C<Mail::SpamAssassin::Plugin>, you
can do this:

    if ($self->can("name_of_method")) {
      eval {
        $self->name_of_method();        # etc.
      }
    } else {
      # take fallback action
    }

The same applies for the public APIs on objects of other types, such as
C<Mail::SpamAssassin::PerMsgStatus>.

=head1 SEE ALSO

C<Mail::SpamAssassin>

C<Mail::SpamAssassin::PerMsgStatus>

http://wiki.apache.org/spamassassin/PluginWritingTips

http://issues.apache.org/SpamAssassin/show_bug.cgi?id=2163

=cut
