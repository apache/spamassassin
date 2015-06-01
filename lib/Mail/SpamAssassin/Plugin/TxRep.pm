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

Mail::SpamAssassin::Plugin::TxRep - Normalize scores with sender reputation records


=head1 SYNOPSIS

The TxRep (Reputation) plugin is designed as an improved replacement of the AWL
(Auto-Whitelist) plugin. It adjusts the final message spam score by looking up and
taking in consideration the reputation of the sender.

To try TxRep out, you B<have to> disable the AWL plugin (if present), back up its
database and add a line loading this module in init.pre (AWL may be enabled in v310.pre):

 # loadplugin   Mail::SpamAssassin::Plugin::AWL
   loadplugin   Mail::SpamAssassin::Plugin::TxRep

When AWL is not disabled, TxRep will refuse to run.

Use the supplied 60_txreputation.cf file or add these lines to a .cf file:

 header         TXREP   eval:check_senders_reputation()
 describe       TXREP   Score normalizing based on sender's reputation
 tflags         TXREP   userconf noautolearn
 priority       TXREP   1000


=head1 DESCRIPTION

This plugin is intended to replace the former AWL - AutoWhiteList. Although the
concept and the scope differ, the purpose remains the same - the normalizing of spam
score results based on previous sender's history. The name was intentionally changed
from "whitelist" to "reputation" to avoid any confusion, since the result score can
be adjusted in both directions.

The TxRep plugin keeps track of the average SpamAssassin score for senders.
Senders are tracked using multiple identificators, or their combinations: the  From:
email address, the originating IP and/or an originating block of IPs, sender's domain
name, the DKIM signature, and the HELO name. TxRep then uses the average score to reduce
the variability in scoring from message to message, and modifies the final score by
pushing the result towards the historical average. This improves the accuracy of
filtering for most email.

In comparison with the original AWL plugin, several conceptual changes were implemented
in TxRep:

1. B<Scoring> - at AWL, although it tracks the number of messages received from each
respective sender, when calculating the corrective score at a new message, it does
not take it in count in any way. So for example a sender who previously sent a single
ham message with the score of -5, and then sends a second one with the score of +10,
AWL will issue a corrective score bringing the score towards the -5. With the default
C<auto_whitelist_factor> of 0.5, the resulting score would be only 2.5. And it would be
exactly the same even if the sender previously sent 1,000 messages with the average of
-5. TxRep tries to take the maximal advantage of the collected data, and adjusts the
final score not only with the mean reputation score stored in the database, but also
respecting the number of messages already seen from the sender. You can see the exact
formula in the section L</C<txrep_factor>>.

2. B<Learning> - AWL ignores any spam/ham learning. In fact it acts against it, which
often leads to a frustrating situation, where a user repeatedly tags all messages of a
given sender as spam (resp. ham), but at any new message from the sender, AWL will
adjust the score of the message back to the historical average which does B<not> include
the learned scores. This is now changed at TxRep, and every spam/ham learning will be
recorded in the reputation database, and hence taken in consideration at future email
from the respective sender. See the section L</"LEARNING SPAM / HAM"> for more details.

3. B<Auto-Learning> - in certain situations SpamAssassin may declare a message an
obvious spam resp. ham, and launch the auto-learning process, so that the message can be
re-evaluated. AWL, by design, did not perform any auto-learning adjustments. This plugin
will readjust the stored reputation by the value defined by L</C<txrep_learn_penalty>>
resp. L</C<txrep_learn_bonus>>. Auto-learning score thresholds may be tuned, or the
auto-learning completely disabled, through the setting L</C<txrep_autolearn>>.

4. B<Relearning> - messages that were wrongly learned or auto-learned, can be relearned.
Old reputations are removed from the database, and new ones added instead of them. The
relearning works better when message tracking is enabled through the
L</C<txrep_track_messages>> option. Without it, the relearned score is simply added to
the reputation, without removing the old ones.

5. B<Aging> - with AWL, any historical record of given sender has the same weight. It
means that changes in senders behavior, or modified SA rules may take long time, or
be virtually negated by the AWL normalization, especially at senders with high count
of past messages, and low recent frequency. It also turns to be particularly
counterproductive when the administrator detects new patterns in certain messages, and
applies new rules to better tag such messages as spam or ham. AWL will practically
eliminate the effect of the new rules, by adjusting the score back towards the (wrong)
historical average. Only setting the C<auto_whitelist_factor> lower would help, but in
the same time it would also reduce the overall impact of AWL, and put doubts on its
purpose. TxRep, besides the L</C<txrep_factor>> (replacement of the C<auto_whitelist_factor>),
introduces also the L</C<txrep_dilution_factor>> to help coping with this issue by
progressively reducing the impact of past records. More details can be found in the
description of the factor below.

6. B<Blacklisting and Whitelisting> - when a whitelisting or blacklisting was requested
through SpamAssassin's API, AWL adjusts the historical total score of the plain email
address without IP (and deleted records bound to an IP), but since during the reception 
new records with IP will be added, the blacklisted entry would cease acting during 
scanning. TxRep always uses the record of th plain email address without IP together 
with the one bound to an IP address, DKIM signature, or SPF pass (unless the weight 
factor for the EMAIL reputation is set to zero). AWL uses the score of 100 (resp. -100) 
for the blacklisting (resp. whitelisting) purposes. TxRep increases the value 
proportionally to the weight factor of the EMAIL reputation. It is explained in details 
in the section L</BLACKLISTING / WHITELISTING>. TxRep can blacklist or whitelist also
IP addresses, domain names, and dotless HELO names.

7. B<Sender Identification> - AWL identifies a sender on the basis of the email address
used, and the originating IP address (better told its part defined by the mask setting).
The main purpose of this measure is to avoid assigning false good scores to spammers who
spoof known email addresses. The disadvantage appears at senders who send from frequently
changing locations or even when connecting through dynamical IP addresses that are not
within the block defined by the mask setting. Their score is difficult or sometimes
impossible to track. Another disadvantage is, for example, at a spammer persistently
sending spam from the same IP address, just under different email addresses. AWL will not
find his previous scores, unless he reuses the same email address again. TxRep uses several
identificators, and creates separate database entries for each of them. It tracks not only
the email/IP address combination like AWL, but also the standalone email address (regardless
of the originating IP), the standalone IP (regardless of email address used), the domain
name of the email address, the DKIM signature, and the HELO name of the connecting PC. The
influence of each individual identificator may be tuned up with the help of weight factors
described in the section L</REPUTATION WEIGHTS>.

8. B<Message Tracking> - TxRep (optionally) keeps track of already scanned and/or learned
message ID's. This is useful for avoiding to strengthen the reputation score by simply
rescanning or relearning the same message multiple times. In the same time it also allows
the proper relearning of once wrongly learned messages, or relearning them after the
learn penalty or bonus were changed. See the option L</C<txrep_track_messages>>.

9. B<User and Global Storages> - usually it is recommended to use the per-user setup
of SpamAssassin, because each user may have quite different requirements, and may receive
quite different sort of email. Especially when using the Bayesian and AWL plugins,
the efficiency is much better when SpamAssassin is learned spam and ham separately
for each user. However, the disadvantage is that senders and emails already learned
many times by different users, will need to be relearned without any recognized history,
anytime they arrive to another user. TxRep uses the advantages of both systems. It can
use dual storages: the global common storage, where all email processed by SpamAssassin
is recorded, and a local storage separate for each user, with reputation data from his
email only. See more details at the setting L</C<txrep_user2global_ratio>>.

10. B<Outbound Whitelisting> - when a local user sends messages to an email address, we
assume that he needs to see the eventual answer too, hence the recipient's address should
be whitelisted. When SpamAssassin is used for scanning outgoing email too, when local
users use the SMTP server where SA is installed, for sending email, and when internal
networks are defined, TxREP will improve the reputation of all 'To:' and 'CC' addresses
from messages originating in the internal networks. Details can be found at the setting
L</C<txrep_whitelist_out>>.

Both plugins (AWL and TxREP) cannot coexist. It is necessary to disable the AWL to allow
TxRep running. TxRep reuses the database handling of the original AWL module, and some
its parameters bound to the database handler modules. By default, TxRep creates its own
database, but the original auto-whitelist can be reused as a starting point. The AWL
database can be renamed to the name defined in TxRep settings, and TxRep will start
using it. The original auto-whitelist database has to be backed up, to allow switching
back to the original state.

The spamassassin/Plugin/TxRep.pm file replaces both spamassassin/Plugin/AWL.pm and
spamassassin/AutoWhitelist.pm. Another two AWL files, spamassassin/DBBasedAddrList.pm
and spamassassin/SQLBasedAddrList.pm are still needed.


=head1 TEMPLATE TAGS

This plugin module adds the following C<tags> that can be used as
placeholders in certain options.  See L<Mail::SpamAssassin::Conf>
for more information on TEMPLATE TAGS.

 _TXREP_XXX_Y_          TXREP modifier
 _TXREP_XXX_Y_MEAN_     Mean score on which TXREP modification is based
 _TXREP_XXX_Y_COUNT_    Number of messages on which TXREP modification is based
 _TXREP_XXX_Y_PRESCORE_ Score before TXREP
 _TXREP_XXX_Y_UNKNOW_   New sender (not found in the TXREP list)

The XXX part of the tag takes the form of one of the following IDs, depending
on the reputation checked: EMAIL, EMAIL_IP, IP, DOMAIN, or HELO. The _Y appendix
ID is used only in the case of dual storage, and takes the form of either _U (for
user storage reputations), or _G (for global storage reputations).

=cut # ....................................................................
package Mail::SpamAssassin::Plugin::TxRep;

use strict;
use warnings;
use bytes;
use re 'taint';

use NetAddr::IP 4.000;                          # qw(:upper);
use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Plugin::Bayes;
use Mail::SpamAssassin::Util qw(untaint_var);
use Mail::SpamAssassin::Logger;

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);


###########################################################################
sub new {                       # constructor: register the eval rule
###########################################################################
  my ($class, $main) = @_;

  $class   = ref($class) || $class;
  my $self = $class->SUPER::new($main);
  bless($self, $class);

  $self->{main}          = $main;
  $self->{conf}          = $main->{conf};
  $self->{factor}        = $main->{conf}->{txrep_factor};
  $self->{ipv4_mask_len} = $main->{conf}->{txrep_ipv4_mask_len};
  $self->{ipv6_mask_len} = $main->{conf}->{txrep_ipv6_mask_len};
  $self->register_eval_rule("check_senders_reputation");
  $self->set_config($main->{conf});

  # only the default conf loaded here, do nothing here requiring
  # the runtime settings
  dbg("TxRep: new object created");
  return $self;
}


###########################################################################
sub set_config {
###########################################################################
  my($self, $conf) = @_;
  my @cmds;

# -------------------------------------------------------------------------
=head1 USER PREFERENCES

The following options can be used in both site-wide (C<local.cf>) and
user-specific (C<user_prefs>) configuration files to customize how
SpamAssassin handles incoming email messages.

=over 4

=item B<use_txrep>

  0 | 1                 (default: 0)

Whether to use TxRep reputation system.  TxRep tracks the long-term average
score for each sender and then shifts the score of new messages toward that
long-term average.  This can increase or decrease the score for messages,
depending on the long-term behavior of the particular correspondent.

Note that certain tests are ignored when determining the final message score:

 - rules with tflags set to 'noautolearn'

=cut  # ...................................................................
  push (@cmds, {
    setting     => 'use_txrep',
    default     => 0,
    type        => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL
  });


# -------------------------------------------------------------------------
=item B<txrep_factor>

 range [0..1]           (default: 0.5)

How much towards the long-term mean for the sender to regress a message.
Basically, the algorithm is to track the long-term total score and the count
of messages for the sender (C<total> and C<count>), and then once we have
otherwise fully calculated the score for this message (C<score>), we calculate
the final score for the message as:

 finalscore = score + factor * (total + score)/(count + 1)

So if C<factor> = 0.5, then we'll move to half way between the calculated
score and the new mean value.  If C<factor> = 0.3, then we'll move about 1/3
of the way from the score toward the mean.  C<factor> = 1 means use the
long-term mean including also the new unadjusted score; C<factor> = 0 mean
just use the calculated score, disabling so the score averaging, though still
recording the reputation to the database.

=cut  # ...................................................................
  push (@cmds, {
    setting     => 'txrep_factor',
    default     => 0.5,
    type        => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
    code        => sub {
        my ($self, $key, $value, $line) = @_;
        if ($value < 0 || $value > 1.0) {return $Mail::SpamAssassin::Conf::INVALID_VALUE;}
        $self->{txrep_factor} = $value;
    }
  });


# -------------------------------------------------------------------------
=item B<txrep_dilution_factor>

 range [0.7..1.0]               (default: 0.98)

At any new email from given sender, the historical reputation records are "diluted",
or "watered down" by certain fraction given by this factor. It means that the
influence of old records will progressively diminish with every new message from
given sender. This is important to allow a more flexible handling of changes in
sender's behavior, or new improvements or changes of local SA rules.

Without any dilution expiry (dilution factor set to 1), the new message score is
simply add to the total score of given sender in the reputation database. When
dilution is used (factor < 1), the impact of the historical reputation average is
reduced by the factor before calculating the new average, which in turn is then
used to adjust the new total score to be stored in the database.

 newtotal = (oldcount + 1) * (newscore + dilution * oldtotal) / (dilution * oldcount + 1)

In other words, it means that the older a message is, the less and less impact
on the new average its original spam score has. For example if we set the factor
to 0.9 (meaning dilution by 10%), the score of the new message will be recorded
to its 100%, the last score of the same sender to 90%, the second last to 81%
(0.9 * 0.9 = 0.81), and for example the 10th last message just to 35%.

At stable systems, we recommend keeping the factor close to 1 (but still lower
than 1). At systems where SA rules tuning and spam learning is still in progress,
lower factors will help the reputation to quicker adapt any modifications. In
the same time, it will also reduce the impact of the historical reputation
though.

=cut  # ...................................................................
  push (@cmds, {
    setting     => 'txrep_dilution_factor',
    default     => 0.98,
    type        => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
    code        => sub {
        my ($self, $key, $value, $line) = @_;
        if ($value < 0.7 || $value > 1.0) {return $Mail::SpamAssassin::Conf::INVALID_VALUE;}
        $self->{txrep_dilution_factor} = $value;
    }
  });


# TODO, not implemented yet, hence no advertising until then
# -------------------------------------------------------------------------
#=item B<txrep_expiry_days>
#
# range [0..10000]              (default: 365)
#
#The scores of of messages can be removed from the total reputation, and the
#message tracking entry removed from the database after given number of days.
#It helps keeping the database growth under control, and it also reduces the
#influence of old scores on the current reputation (both scoring methods, and
#sender's behavior might have changed over time).
#
#=cut  # ...................................................................
  push (@cmds, {
    setting     => 'txrep_expiry_days',
    default     => 365,
    type        => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
    code        => sub {
        my ($self, $key, $value, $line) = @_;
        if ($value < 0 || $value > 10000) {return $Mail::SpamAssassin::Conf::INVALID_VALUE;}
        $self->{txrep_expiry_days} = $value;
    }
  });


# -------------------------------------------------------------------------
=item B<txrep_learn_penalty>

 range [0..200]         (default: 20)

When SpamAssassin is trained a SPAM message, the given penalty score will
be added to the total reputation score of the sender, regardless of the real
spam score. The impact of the penalty will be the smaller the higher is the
number of messages that the sender already has in the TxRep database.

=cut  # ...................................................................
  push (@cmds, {
    setting     => 'txrep_learn_penalty',
    default     => 20,
    type        => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
    code        => sub {
        my ($self, $key, $value, $line) = @_;
        if ($value < 0 || $value > 200) {return $Mail::SpamAssassin::Conf::INVALID_VALUE;}
        $self->{txrep_learn_penalty} = $value;
    }
  });


# -------------------------------------------------------------------------
=item B<txrep_learn_bonus>

 range [0..200]         (default: 20)

When SpamAssassin is trained a HAM message, the given penalty score will be
deduced from the total reputation score of the sender, regardless of the real
spam score. The impact of the penalty will be the smaller the higher is the
number of messages that the sender already has in the TxRep database.

=cut  # ...................................................................
  push (@cmds, {
    setting     => 'txrep_learn_bonus',
    default     => 20,
    type        => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
    code        => sub {
        my ($self, $key, $value, $line) = @_;
        if ($value < 0 || $value > 200) {return $Mail::SpamAssassin::Conf::INVALID_VALUE;}
        $self->{txrep_learn_bonus} = $value;
    }
  });


# -------------------------------------------------------------------------
=item B<txrep_autolearn>

 range [0..5]                   (default: 0)

When SpamAssassin declares a message a clear spam resp. ham during the mesage
scan, and launches the auto-learn process, sender reputation scores of given
message will be adjusted by the value of the option L</C<txrep_learn_penalty>>,
resp. the L</C<txrep_learn_bonus>> in the same way as during the manual learning.
Value 0 at this option disables the auto-learn reputation adjustment - only the
score calculated before the auto-learn will be stored to the reputation database.

=cut  # ...................................................................
  push (@cmds, {
    setting     => 'txrep_autolearn',
    default     => 0,
    type        => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
    code        => sub {
        my ($self, $key, $value, $line) = @_;
        if ($value < 0 || $value > 5) {return $Mail::SpamAssassin::Conf::INVALID_VALUE;}
        $self->{txrep_autolearn} = $value;
    }
  });


# -------------------------------------------------------------------------
=item B<txrep_track_messages>

  0 | 1                 (default: 1)

Whether TxRep should keep track of already scanned and/or learned messages.
When enabled, an additional record in the reputation database will be created
to avoid false score adjustments due to repeated scanning of the same message,
and to allow proper relearning of messages that were either previously wrongly
learned, or need to be relearned after modifying the learn penalty or bonus.

=cut  # ...................................................................
  push (@cmds, {
    setting     => 'txrep_track_messages',
    default     => 1,
    type        => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL
  });


# -------------------------------------------------------------------------
=item B<txrep_whitelist_out>

 range [0..200]         (default: 10)

When the value of this setting is greater than zero, recipients of messages sent from
within the internal networks will be whitelisted through improving their total reputation
score with the number of points defined by this setting. Since the IP address and other
sender identificators are not known when sending the email, only the reputation of the
standalone email is being whitelisted. The domain name is intentionally also left
unaffected. The outbound whitelisting can only work when SpamAssassin is set up to scan
also outgoing email, when local users use the SMTP server for sending email, and when
C<internal_networks> are defined in SpamAssassin configuration. The improving of the
reputation happens at every message sent from internal networks, so the more messages is
being sent to the recipient, the better reputation his email address will have.


=cut  # ...................................................................
  push (@cmds, {
    setting     => 'txrep_whitelist_out',
    default     => 10,
    type        => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
    code        => sub {
        my ($self, $key, $value, $line) = @_;
        if ($value < 0 || $value > 200) {return $Mail::SpamAssassin::Conf::INVALID_VALUE;}
        $self->{txrep_whitelist_out} = $value;
    }
  });


# -------------------------------------------------------------------------
=item B<txrep_ipv4_mask_len>

 range [0..32]          (default: 16)

The AWL database keeps only the specified number of most-significant bits
of an IPv4 address in its fields, so that different individual IP addresses
within a subnet belonging to the same owner are managed under a single
database record. As we have no information available on the allocated
address ranges of senders, this CIDR mask length is only an approximation.
The default is 16 bits, corresponding to a former class B. Increase the
number if a finer granularity is desired, e.g. to 24 (class C) or 32.
A value 0 is allowed but is not particularly useful, as it would treat the
whole internet as a single organization. The number need not be a multiple
of 8, any split is allowed.

=cut  # ...................................................................
  push (@cmds, {
    setting     => 'txrep_ipv4_mask_len',
    default     => 16,
    type        => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
    code        => sub {
        my ($self, $key, $value, $line) = @_;
        if (!defined $value || $value eq '')
            {return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;}
        elsif ($value !~ /^\d+$/ || $value < 0 || $value > 32)
            {return $Mail::SpamAssassin::Conf::INVALID_VALUE;}
        $self->{txrep_ipv4_mask_len} = $value;
    }
  });


# -------------------------------------------------------------------------
=item B<txrep_ipv6_mask_len>

 range [0..128]         (default: 48)

The AWL database keeps only the specified number of most-significant bits
of an IPv6 address in its fields, so that different individual IP addresses
within a subnet belonging to the same owner are managed under a single
database record. As we have no information available on the allocated address
ranges of senders, this CIDR mask length is only an approximation. The default
is 48 bits, corresponding to an address range commonly allocated to individual
(smaller) organizations. Increase the number for a finer granularity, e.g.
to 64 or 96 or 128, or decrease for wider ranges, e.g. 32.  A value 0 is
allowed but is not particularly useful, as it would treat the whole internet
as a single organization. The number need not be a multiple of 4, any split
is allowed.

=cut  # ...................................................................
  push (@cmds, {
    setting     => 'txrep_ipv6_mask_len',
    default     => 48,
    type        => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
    code        => sub {
        my ($self, $key, $value, $line) = @_;
        if (!defined $value || $value eq '')
            {return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;}
        elsif ($value !~ /^\d+$/ || $value < 0 || $value > 128)
            {return $Mail::SpamAssassin::Conf::INVALID_VALUE;}
        $self->{txrep_ipv6_mask_len} = $value;
    }
  });


# -------------------------------------------------------------------------
=item B<user_awl_sql_override_username>

  string                (default: undefined)

Used by the SQLBasedAddrList storage implementation.

If this option is set the SQLBasedAddrList module will override the set
username with the value given.  This can be useful for implementing global
or group based TxRep databases.

=cut  # ...................................................................
  push (@cmds, {
    setting     => 'user_awl_sql_override_username',
    default     => '',
    type        => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING
  });


# -------------------------------------------------------------------------
=item B<txrep_user2global_ratio>

 range [0..10]          (default: 0)

When the option txrep_user2global_ratio is set to a value greater than zero, and
if the server configuration allows it, two data storages will be used - user and
global (server-wide) storages.

User storage keeps only senders who send messages to the respective recipient,
and will reflect also the corrected/learned scores, when some messages are marked
by the user as spam or ham, or when the sender is whitelisted or blacklisted
through the API of SpamAssassin.

Global storage keeps the reputation data of all messages processed by SpamAssassin
with their spam scores and spam/ham learning data from all users on the server.
Hence, the module will return a reputation value even at senders not known to the
current recipient, as long as he already sent email to anyone else on the server.

The value of the txrep_user2global_ratio parameter controls the impact of each
of the two reputations. When equal to 1, both the global and the user score will
have the same impact on the result. When set to 2, the reputation taken from
the user storage will have twice the impact of the global value. The final value
of the TXREP tag will be calculated as follows:

 total = ( ratio * user + global ) / ( ratio + 1 )

When no reputation is found in the user storage, and a global reputation is
available, the global storage is used fully, without applying the ratio.

When the ratio is set to zero, only the default storage will be used. And it
then depends whether you use the global, or the local user storage by default,
which in turn is controlled either by the parameter user_awl_sql_override_username
(in case of SQL storage), or the C</auto_whitelist_path> parameter (in case of
Berkeley database).

When this dual storage is enabled, and no global storage is defined by the
above mentioned parameters for the Berkeley or SQL databases, TxRep will attempt
to use a generic storage - user 'GLOBAL' in case of SQL, and in the case of
Berkeley database it uses the path defined by '__local_state_dir__/tx-reputation',
which typically renders into /var/db/spamassassin/tx-reputation. When the default
storages are not available, or are not writable, you would have to set the global
storage with the help of the C<user_awl_sql_override_username> resp.
C<auto_whitelist_path settings>.

Please note that some SpamAssassin installations run always under the same user
ID. In such case it is pointless enabling the dual storage, because it would
maximally lead to two identical global storages in different locations.

This feature is disabled by default.
=cut  # ...................................................................
  push (@cmds, {
    setting     => 'txrep_user2global_ratio',
    default     => 0,
    type        => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code        => sub {
        my ($self, $key, $value, $line) = @_;
        if ($value < 0 || $value > 10) {return $Mail::SpamAssassin::Conf::INVALID_VALUE;}
        $self->{txrep_user2global_ratio} = $value;
    }
  });


# -------------------------------------------------------------------------
=item B<auto_whitelist_distinguish_signed>

 (default: 1 - enabled)

Used by the SQLBasedAddrList storage implementation.

If this option is set the SQLBasedAddrList module will keep separate
database entries for DKIM-validated e-mail addresses and for non-validated
ones. A pre-requisite when setting this option is that a field awl.signedby
exists in a SQL table, otherwise SQL operations will fail (which is why we
need this option at all - for compatibility with pre-3.3.0 database schema).
A plugin DKIM should also be enabled, as otherwise there is no benefit from
turning on this option.

=cut  # ...................................................................
  push (@cmds, {
    setting     => 'auto_whitelist_distinguish_signed',
    default     => 1,
    type        => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL
  });


=item B<txrep_spf>

  0 | 1                 (default: 1)

When enabled, TxRep will treat any IP address using a given email address as
the same authorized identity, and will not associate any IP address with it.
(The same happens with valid DKIM signatures. No option available for DKIM).

Note: at domains that define the useless SPF +all (pass all), no IP would be
ever associated with the email address, and all addresses (incl. the froged
ones) would be treated as coming from the authorized source. However, such
domains are hopefuly rare, and ask for this kind of treatment anyway.

=back

=cut  # ...................................................................
  push (@cmds, {
    setting     => 'txrep_spf',
    default     => 1,
    type        => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL
  });


# -------------------------------------------------------------------------
=head2 REPUTATION WEIGHTS

The overall reputation of the sender comprises several elements:

=over 4

=item 1) The reputation of the 'From' email address bound to the originating IP
         address fraction (see the mask parameters for details)

=item 2) The reputation of the 'From' email address alone (regardless the IP
         address being currently used)

=item 3) The reputation of the domain name of the 'From' email address

=item 4) The reputation of the originating IP address, regardless of sender's email address

=item 5) The reputation of the HELO name of the originating computer (if available)

=back

Each of these partial reputations is weighted with the help of these parameters,
and the overall reputation is calculation as the sum of the individual
reputations divided by the sum of all their weights:

 sender_reputation = weight_email    * rep_email    +
                     weight_email_ip * rep_email_ip +
                     weight_domain   * rep_domain   +
                     weight_ip       * rep_ip       +
                     weight_helo     * rep_helo

You can disable the individual partial reputations by setting their respective
weight to zero. This will also reduce the size of the database, since each
partial reputation requires a separate entry in the database table. Disabling
some of the partial reputations in this way may also help with the performance
on busy servers, because the respective database lookups and processing will
be skipped too.

=over 4

=item B<txrep_weight_email>

 range [0..10]          (default: 3)

This weight factor controls the influence of the reputation of the standalone
email address, regardless of the originating IP address. When adjusting the
weight, you need to keep on mind that an email address can be easily spoofed,
and hence spammers can use 'from' email addresses belonging to senders with
good reputation. From this point of view, the email address bound to the
originating IP address is a more reliable indicator for the overall reputation.

On the other hand, some reputable senders may be sending from a bigger number
of IP addresses, so looking for the reputation of the standalone email address
without regarding the originating IP has some sense too.

We recommend using a relatively low value for this partial reputation.

=cut  # ...................................................................
  push (@cmds, {
    setting     => 'txrep_weight_email',
    default     => 3,
    type        => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
    code        => sub {
        my ($self, $key, $value, $line) = @_;
        if ($value < 0 || $value > 10) {return $Mail::SpamAssassin::Conf::INVALID_VALUE;}
        $self->{txrep_weight_email} = $value;
    }
  });

# -------------------------------------------------------------------------
=item B<txrep_weight_email_ip>

 range [0..10]          (default: 10)

This is the standard reputation used in the same way as it was by the original
AWL plugin. Each sender's email address is bound to the originating IP, or
its part as defined by the txrep_ipv4_mask_len or txrep_ipv6_mask_len parameters.

At a user sending from multiple locations, diverse mail servers, or from a dynamic
IP range out of the masked block, his email address will have a separate reputation
value for each of the different (partial) IP addresses.

When the option auto_whitelist_distinguish_signed is enabled, in contrary to
the original AWL module, TxRep does not record the IP address when DKIM
signature is detected. The email address is then not bound to any IP address, but
rather just to the DKIM signature, since it is considered that it authenticates
the sender more reliably than the IP address (which can also vary).

This is by design the most relevant reputation, and its weight should be kept
high.

=cut  # ...................................................................
  push (@cmds, {
    setting     => 'txrep_weight_email_ip',
    default     => 10,
    type        => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
    code        => sub {
        my ($self, $key, $value, $line) = @_;
        if ($value < 0 || $value > 10) {return $Mail::SpamAssassin::Conf::INVALID_VALUE;}
        $self->{txrep_weight_email_ip} = $value;
    }
  });

# -------------------------------------------------------------------------
=item B<txrep_weight_domain>

 range [0..10]          (default: 2)

Some spammers may use always their real domain name in the email address,
just with multiple or changing local parts. This reputation will record the
spam scores of all messages send from the respective domain, regardless of
the local part (user name) used.

Similarly as with the email_ip reputation, the domain reputation is also
bound to the originating address (or a masked block, if mask parameters used).
It avoids giving false reputation based on spoofed email addresses.

In case of a DKIM signature detected, the signature signer is used instead
of the domain name extracted from the email address. It is considered that
the signing authority is responsible for sending email of any domain name,
hence the same reputation applies here.

The domain reputation will give relevant picture about the owner of the
domain in case of small servers, or corporation with strict policies, but
will be less relevant for freemailers like Gmail, Hotmail, and similar,
because both ham and spam may be sent by their users.

The default value is set relatively low. Higher weight values may be useful,
but we recommend caution and observing the scores before increasing it.

=cut  # ...................................................................
  push (@cmds, {
    setting     => 'txrep_weight_domain',
    default     => 2,
    type        => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
    code        => sub {
        my ($self, $key, $value, $line) = @_;
        if ($value < 0 || $value > 10) {return $Mail::SpamAssassin::Conf::INVALID_VALUE;}
        $self->{txrep_weight_domain} = $value;
    }
  });

# -------------------------------------------------------------------------
=item B<txrep_weight_ip>

 range [0..10]          (default: 4)

Spammers can send through the same relay (incl. compromised hosts) under a
multitude of email addresses. This is the exact case when the IP reputation
can help. This reputation is a kind of a local RBL.

The weight is set by default lower than for the email_IP reputation, because
there may be cases when the same IP address hosts both spammers and acceptable
senders (for example the marketing department of a company sends you spam, but
you still need to get messages from their billing address).

=cut  # ...................................................................
  push (@cmds, {
    setting     => 'txrep_weight_ip',
    default     => 4,
    type        => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
    code        => sub {
        my ($self, $key, $value, $line) = @_;
        if ($value < 0 || $value > 10) {return $Mail::SpamAssassin::Conf::INVALID_VALUE;}
        $self->{txrep_weight_ip} = $value;
    }
  });

# -------------------------------------------------------------------------
=item B<txrep_weight_helo>

 range [0..10]          (default: 0.5)

Big number of spam messages come from compromised hosts, often personal computers,
or top-boxes. Their NetBIOS names are usually used as the HELO name when connecting
to your mail server. Some of the names are pretty generic and hence may be shared by
a big number of hosts, but often the names are quite unique and may be a good
indicator for detecting a spammer, despite that he uses different email and IP
addresses (spam can come also from portable devices).

No IP address is bound to the HELO name when stored to the reputation database.
This is intentional, and despite the possibility that numerous devices may share
some of the HELO names.

This option is still considered experimental, hence the low weight value, but after
some testing it could be likely at least slightly increased.

=cut  # ...................................................................
  push (@cmds, {
    setting     => 'txrep_weight_helo',
    default     => 0.5,
    type        => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
    code        => sub {
        my ($self, $key, $value, $line) = @_;
        if ($value < 0 || $value > 10) {return $Mail::SpamAssassin::Conf::INVALID_VALUE;}
        $self->{txrep_weight_helo} = $value;
    }
  });


# -------------------------------------------------------------------------
=back

=head1 ADMINISTRATOR SETTINGS

These settings differ from the ones above, in that they are considered 'more
privileged' -- even more than the ones in the B<PRIVILEGED SETTINGS> section.
No matter what C<allow_user_rules> is set to, these can never be set from a
user's C<user_prefs> file.

=over 4

=item B<txrep_factory module>

 (default: Mail::SpamAssassin::DBBasedAddrList)

Select alternative database factory module for the TxRep database.

=cut  # ...................................................................
  push (@cmds, {
    setting      => 'txrep_factory',
    is_admin     => 1,
    default      => 'Mail::SpamAssassin::DBBasedAddrList',
    type         => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING
  });


# -------------------------------------------------------------------------
=item B<auto_whitelist_path /path/filename>

 (default: ~/.spamassassin/tx-reputation)

This is the TxRep directory and filename.  By default, each user
has their own reputation database in their C<~/.spamassassin> directory with
mode 0700.  For system-wide SpamAssassin use, you may want to share this
across all users.

=cut  # ...................................................................
  push (@cmds, {
    setting      => 'auto_whitelist_path',
    is_admin     => 1,
    default      => '__userstate__/tx-reputation',
    type         => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code         => sub {
        my ($self, $key, $value, $line) = @_;
        unless (defined $value && $value !~ /^$/) {return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;}
        if (-d $value)                            {return $Mail::SpamAssassin::Conf::INVALID_VALUE; }
        $self->{txrep_path} = $value;
    }
  });


# -------------------------------------------------------------------------
=item B<auto_whitelist_db_modules Module ...>

 (default: see below)

What database modules should be used for the TxRep storage database
file.   The first named module that can be loaded from the Perl include path
will be used.  The format is:

  PreferredModuleName SecondBest ThirdBest ...

ie. a space-separated list of Perl module names.  The default is:

  DB_File GDBM_File SDBM_File

NDBM_File is not supported (see SpamAssassin bug 4353).

=cut  # ...................................................................
  push (@cmds, {
    setting      => 'auto_whitelist_db_modules',
    is_admin     => 1,
    default      => 'DB_File GDBM_File SDBM_File',
    type         => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING
  });


# -------------------------------------------------------------------------
=item B<auto_whitelist_file_mode>

 (default: 0700)

The file mode bits used for the TxRep directory or file.

Make sure you specify this using the 'x' mode bits set, as it may also be used
to create directories.  However, if a file is created, the resulting file will
not have any execute bits set (the umask is set to 0111).

=cut  # ...................................................................
  push (@cmds, {
    setting      => 'auto_whitelist_file_mode',
    is_admin     => 1,
    default      => '0700',
    type         => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
    code         => sub {
        my ($self, $key, $value, $line) = @_;
        if ($value !~ /^0?[0-7]{3}$/) {
            return $Mail::SpamAssassin::Conf::INVALID_VALUE;
        }
        $self->{txrep_file_mode} = untaint_var($value);
    }
  });


# -------------------------------------------------------------------------
=item B<user_awl_dsn DBI:databasetype:databasename:hostname:port>

Used by the SQLBasedAddrList storage implementation.

This will set the DSN used to connect.  Example:
C<DBI:mysql:spamassassin:localhost>

=cut  # ...................................................................
  push (@cmds, {
    setting      => 'user_awl_dsn',
    is_admin     => 1,
    type         => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING
  });


# -------------------------------------------------------------------------
=item B<user_awl_sql_username username>

Used by the SQLBasedAddrList storage implementation.

The authorized username to connect to the above DSN.

=cut  # ...................................................................
  push (@cmds, {
    setting      => 'user_awl_sql_username',
    is_admin     => 1,
    type         => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING
  });


# -------------------------------------------------------------------------
=item B<user_awl_sql_password password>

Used by the SQLBasedAddrList storage implementation.

The password for the database username, for the above DSN.

=cut  # ...................................................................
  push (@cmds, {
    setting      => 'user_awl_sql_password',
    is_admin     => 1,
    type         => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING
  });


# -------------------------------------------------------------------------
=item B<user_awl_sql_table tablename>

 (default: txrep)

Used by the SQLBasedAddrList storage implementation.

The table name where reputation is to be stored in, for the above DSN.

=back

=cut  # ...................................................................
  push (@cmds, {
    setting      => 'user_awl_sql_table',
    is_admin     => 1,
    default      => 'txrep',
    type         => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING
  });

  $conf->{parser}->register_commands(\@cmds);
}


###########################################################################
sub _message {
###########################################################################
  my ($self, $value, $msg) = @_;
  print "SpamAssassin TxRep: $value\n" if ($msg);
  dbg("TxRep: $value");
}


###########################################################################
sub _fail_exit {
###########################################################################
  my ($self, $err) = @_;
  my $eval_stat = ($err ne '') ? $err : "errno=$!";
  chomp $eval_stat;
  warn("TxRep: open of TxRep file failed: $eval_stat\n");
  if (!defined $self->{txKeepStoreTied}) {$self->finish();}
  return 0;
}


###########################################################################
sub _fn_envelope {
###########################################################################
  my ($self, $args, $value, $msg) = @_;

  unless ($self->{main}->{conf}->{use_txrep}){                                  return 0;}
  unless ($args->{address}) {$self->_message($args->{cli_p},"failed ".$msg);    return 0;}

  my $factor =	$self->{conf}->{txrep_weight_email} +
		$self->{conf}->{txrep_weight_email_ip} +
		$self->{conf}->{txrep_weight_domain} +
		$self->{conf}->{txrep_weight_ip} +
		$self->{conf}->{txrep_weight_helo};
  my $sign = $args->{signedby};
  my $id     = $args->{address};
  if ($args->{address} =~ /,/) {
    $sign = $args->{address};
    $sign =~ s/^.*,//g;
    $id   =~ s/,.*$//g;
  }

  # simplified regex used for IP detection (possible FP at a domain is not critical)
  if ($id !~ /\./ && $self->{conf}->{txrep_weight_helo}) 
	{$factor /= $self->{conf}->{txrep_weight_helo}; $sign = 'helo';}
  elsif ($id =~ /^[a-f\d\.:]+$/ && $self->{conf}->{txrep_weight_ip})
	{$factor /= $self->{conf}->{txrep_weight_ip};}
  elsif ($id =~ /@/ && $self->{conf}->{txrep_weight_email})
	{$factor /= $self->{conf}->{txrep_weight_email};}
  elsif ($id !~ /@/ && $self->{conf}->{txrep_weight_domain})
	{$factor /= $self->{conf}->{txrep_weight_domain};}
  else	{$factor  = 1;}

  $self->open_storages();
  my $score  = (!defined $value)? undef : $factor * $value;
  my $status = $self->modify_reputation($id, $score, $sign);
  dbg("TxRep: $msg %s (score %s) %s", $id, $score || 'undef', $sign || '');
  eval {
    $self->_message($args->{cli_p}, ($status?"":"error ") . $msg . ": " . $id);
    if (!defined $self->{txKeepStoreTied}) {$self->finish();}
    1;
  } or return $self->_fail_exit( $@ );
  return $status;
}



# -------------------------------------------------------------------------
=head1 BLACKLISTING / WHITELISTING

When asked by SpamAssassin to blacklist or whitelist a user, the TxRep
plugin adds a score of 100 (for blacklisting) or -100 (for whitelisting)
to the given sender's email address. At a plain address without any IP
address, the value is multiplied by the ratio of total reputation
weight to the EMAIL reputation weight to account for the reduced impact
of the standalone EMAIL reputation when calculating the overall reputation.

   total_weight = weight_email + weight_email_ip + weight_domain + weight_ip + weight_helo
   blacklisted_reputation = 100 * total_weight / weight_email

When a standalone email address is blacklisted/whitelisted, all records
of the email address bound to an IP address, DKIM signature, or a SPF pass
will be removed from the database, and only the standalone record is kept.

Besides blacklisting/whitelisting of standalone email addresses, the same
method may be used also for blacklisting/whitelisting of IP addresses,
domain names, and HELO names (only dotless Netbios HELO names can be used).

When whitelisting/blacklisting an email address or domain name, you can
bind them to a specified DKIM signature or SPF record by appending the 
DKIM signing domain or the tag 'spf' after the ID in the following way:

 spamassassin --add-addr-to-blacklist=spamming.biz,spf
 spamassassin --add-addr-to-whitelist=friend@good.org,good.org

When a message contains both a DKIM signature and an SPF pass, the DKIM
signature takes the priority, so the record bound to the 'spf' tag won't 
be checked. Only email addresses and domains can be bound to DKIM or SPF.
Records of IP adresses and HELO names are always without DKIM/SPF.

In case of dual storage, the black/whitelisting is performed only in the
default storage.

=cut
######################################################## plugin hooks #####
sub blacklist_address {my $self=shift; return $self->_fn_envelope(@_,  100, "blacklisting address");}
sub whitelist_address {my $self=shift; return $self->_fn_envelope(@_, -100, "whitelisting address");}
sub remove_address    {my $self=shift; return $self->_fn_envelope(@_,undef, "removing address");}
###########################################################################


# -------------------------------------------------------------------------
=head1 REPUTATION LOGICS

1. The most significant sender identificator is equally as at AWL, the
   combination of the email address and the originating IP address, resp.
   its part defined by the IPv4 resp. IPv6 mask setting.

2. No IP checking for standalone EMAIL address reputation

3. No signature checking for IP reputation, and for HELO name reputation

4. The EMAIL_IP weight, and not the standalone EMAIL weight is used when
   no IP address is available (EMAIL_IP is the main indicator, and has
   the highest weight)

5. No IP checking at signed emails (signature authenticates the email
   instead of the IP address)

6. No IP checking at SPF pass (we assume the domain owner is responsable
   for all IP's he authorizes to send from, hence we use the same identity
   for all of them)

7. No signature used for standalone EMAIL reputation (would be redundant,
   since no IP is used at signed EMAIL_IP reputation, and we would store
   two identical hits)

8. When available, the DKIM signer is used instead of the domain name for
   the DOMAIN reputation

9. No IP and no signature used for HELO reputation (despite the possibility
   of the possible existence of multiple computers with the same HELO)

10. The full (unmasked IP) address is used (in the address field, instead the
    IP field) for the standalone IP reputation

=cut
###########################################################################
sub check_senders_reputation {
###########################################################################
  my ($self, $pms) = @_;

# just for the development debugging
# use Data::Printer;
# dbg("TxRep: DEBUG DUMP of pms: %s, %s", $pms, p($pms));

  my $autolearn = defined $self->{autolearn};
  $self->{last_pms} = $self->{autolearn} = undef;

  return 0 unless ($self->{conf}->{use_txrep});
  if ($self->{conf}->{use_auto_whitelist}) {
    warn("TxRep: cannot run when Auto-Whitelist is enabled. Please disable it!\n");
    return 0;
  }
  if ($autolearn && !$self->{conf}->{txrep_autolearn}) {
    dbg("TxRep: autolearning disabled, no more reputation adjusting, quitting");
    return 0;
  }
  my @from = $pms->all_from_addrs();
  if (@from && $from[0] eq 'ignore@compiling.spamassassin.taint.org') {
    dbg("TxRep: no scan in lint mode, quitting");
    return 0;
  }

  my $delta    = 0;
  my $timer    = $self->{main}->time_method("total_txrep");
  my $msgscore = (defined $self->{learning})? $self->{learning} : $pms->get_autolearn_points();
  my $date     = $pms->{msg}->receive_date() || $pms->{date_header_time};
  my $msg_id   = $self->{msgid} ||
                 Mail::SpamAssassin::Plugin::Bayes->get_msgid($pms->{msg}) ||
                 $pms->get('Message-Id') || $pms->get('Message-ID') || $pms->get('MESSAGE-ID') || $pms->get('MESSAGEID');

  my $from   = lc $pms->get('From:addr') || $pms->get('EnvelopeFrom:addr');;
  return 0 unless $from =~ /\S/;
  my $domain = $from;
  $domain =~ s/^.+@//;

  my ($origip, $helo);
  if (defined $pms->{relays_trusted} || defined $pms->{relays_untrusted}) {
    my $trusteds = @{$pms->{relays_trusted}};
    foreach my $rly ( @{$pms->{relays_trusted}}, @{$pms->{relays_untrusted}} ) {
	# Get the last found HELO, regardless of private/public or trusted/untrusted
	# Avoiding a redundant duplicate entry if HELO is equal/similar to another identificator
	if (defined $rly->{helo} && $rly->{helo} !~ /^\[?$rly->{ip}\]?$/ && $rly->{helo} !~ /$domain/i && $rly->{helo} !~ /$from/i ) {
	    $helo   = $rly->{helo};
	}
	# use only trusted ID, but use the first untrusted IP (if available) (AWL bug 6908)
	# at low spam scores (<2) ignore trusted/untrusted
	# set IP to 127.0.0.1 for any internal IP, so that it can be distinguished from none (AWL bug 6357)
	if ((--$trusteds >=  0 || $msgscore<2) && !$msg_id && $rly->{id})            {$msg_id = $rly->{id};}
	if (($trusteds   >= -1 || $msgscore<2) && !$rly->{ip_private} && $rly->{ip}) {$origip = $rly->{ip};}
	if ( $trusteds   >=  0     && !$origip &&  $rly->{ip_private} && $rly->{ip}) {$origip = '127.0.0.1';}
    }
  }

  if ($self->{conf}->{txrep_track_messages}) {
    if ($msg_id) {
        my $msg_rep = $self->check_reputations($pms, 'MSG_ID', $msg_id, undef, $date, undef);
        if (defined $msg_rep && $self->count()) {
            if (defined $self->{learning} && !defined $self->{forgetting}) {
                # already learned, forget only if already learned (count>1), and relearn
                # when only scanned (count=1), go ahead with normal rep scan
                if ($self->count() > 1) {
                    $self->{last_pms} = $pms;                   # cache the pmstatus
                    $self->forget_message($pms->{msg},$msg_id); # sub reentrance OK
                }
            } elsif ($self->{forgetting}) {
                $msgscore = $msg_rep;   # forget the old stored score instead of the one got now
                dbg("TxRep: forgetting stored score %0.3f of message %s", $msgscore || 'undef', $msg_id);
            } else {
                # calculating the delta from the stored message reputation
                $delta = ($msgscore + $self->{conf}->{txrep_factor}*$msg_rep) / (1+$self->{conf}->{txrep_factor}) - $msgscore;
                if ($delta != 0) {
                    $pms->got_hit("TXREP", "TXREP: ", ruletype => 'eval', score => sprintf("%0.3f", $delta));
                }
                dbg("TxRep: message %s already scanned, using old data; post-TxRep score: %0.3f", $msg_id, $pms->{score} || 'undef');
                return 0;
            }
        }       # no stored reputation found, go ahead with normal rep scan
    } else {dbg("TxRep: no message-id available, parsing forced");}
  }             # else no message tracking, go ahead with normal rep scan

  # whitelists recipients at senders from internal networks after checking MSG_ID only
  if ( $self->{conf}->{txrep_whitelist_out} &&
          defined $pms->{relays_internal} &&  @{$pms->{relays_internal}} &&
        (!defined $pms->{relays_external} || !@{$pms->{relays_external}})
     ) {
    foreach my $rcpt ($pms->all_to_addrs()) {
        if ($rcpt) {
            dbg("TxRep: internal sender, whitelisting recipient: $rcpt");
            $self->modify_reputation($rcpt, -1*$self->{conf}->{txrep_whitelist_out}, undef);
        }
    }
  }

  my $signedby = ($self->{conf}->{auto_whitelist_distinguish_signed})? $pms->get_tag('DKIMDOMAIN') : undef;
  dbg("TxRep: active, %s pre-score: %s, autolearn score: %s, IP: %s, address: %s %s",
    $msg_id       || '',
    $pms->{score} || '?',
    $msgscore     || '?',
    $origip       || '?',
    $from         || '?',
    $signedby ? "signed by $signedby" : '(unsigned)'
  );

  my $ip = $origip;
  if ($signedby) {
    $ip       = undef;
    $domain   = $signedby;
  } elsif ($pms->{spf_pass} && $self->{conf}->{txrep_spf}) {
    $ip       = undef;
    $signedby = 'spf';
  }

  my $totalweight      = 0;
  $self->{totalweight} = $totalweight;

                     $delta += $self->check_reputations($pms, 'EMAIL_IP', $from,   $ip,   $signedby, $msgscore);
  if ($domain)      {$delta += $self->check_reputations($pms, 'DOMAIN',   $domain, $ip,   $signedby, $msgscore);}
  if ($helo)        {$delta += $self->check_reputations($pms, 'HELO',     $helo,   undef, 'HELO',    $msgscore);}
  if ($origip) {
    if (!$signedby) {$delta += $self->check_reputations($pms, 'EMAIL',    $from,   undef, undef,     $msgscore);}
                     $delta += $self->check_reputations($pms, 'IP',       $origip, undef, undef,     $msgscore);
  }

  if (!defined $self->{learning}) {
    $delta = ($self->{totalweight})? $self->{conf}->{txrep_factor} * $delta / $self->{totalweight}  :  0;
    if ($delta) {
        $pms->got_hit("TXREP", "TXREP: ", ruletype => 'eval', score => sprintf("%0.3f", $delta));
    }
    $msgscore += $delta;
    if (defined $pms->{score}) {
        dbg("TxRep: post-TxRep score: %.3f", $pms->{score});
    }
  }
  if ($self->{conf}->{txrep_track_messages} && $msg_id) {
    $self->check_reputations($pms, 'MSG_ID', $msg_id, undef, $date, $msgscore);
  }
  if (!defined $self->{txKeepStoreTied}) {$self->finish();}

  return 0;
}


###########################################################################
sub check_reputations {
###########################################################################
  my $self = shift;
  my $delta;

  if ($self->open_storages()) {
    if ($self->{conf}->{txrep_user2global_ratio} && $self->{user_storage} != $self->{global_storage}) {
        my $user   = $self->check_reputation('user_storage',  @_);
        my $global = $self->check_reputation('global_storage',@_);

        $delta = (defined $user && $user==$user) ?
            ( $self->{conf}->{txrep_user2global_ratio} * $user + $global ) / ( 1 + $self->{conf}->{txrep_user2global_ratio} ) :
            $global;
    } else {
        $delta = $self->check_reputation(undef,@_);
    }
  }
  return $delta;
}


###########################################################################
sub check_reputation {
###########################################################################
  my ($self, $storage, $pms, $key, $id, $ip, $signedby, $msgscore) = @_;

  my $delta  = 0;
  my $weight = ($key eq 'MSG_ID')? 1 : eval('$pms->{main}->{conf}->{txrep_weight_'.lc($key).'}');

  if (defined $weight && $weight) {
    my $meanrep;
    my $timer = $self->{main}->time_method('check_txrep_'.lc($key));

    if (defined $storage) {
        $self->{checker} = $self->{$storage};
    }
    my $found  = $self->get_sender($id, $ip, $signedby);
    my $tag_id = (defined $storage)? uc($key.'_'.substr($storage,0,1)) : uc($key);
    if (defined $found && $self->count()) {
        $meanrep = $self->total() / $self->count();
    }
    if ($self->{learning} && defined $msgscore) {
        if (defined $meanrep) {
            # $msgscore<=>0 gives the sign of $msgscore
            $msgscore += ($msgscore<=>0) * abs($meanrep);
        }
        dbg("TxRep: reputation: %s, count: %d, learning: %s, $tag_id: %s",
            defined $meanrep? sprintf("%.3f",$meanrep) : 'none',
            $self->count()      || 0,
            $self->{learning}   || '',
            $id                 || 'none'
        );
    } else {
        $self->{totalweight} += $weight;
        if ($key eq 'MSG_ID' && $self->count() > 0) {
            $delta = $self->total() / $self->count();
	    $pms->set_tag('TXREP'.$tag_id,              sprintf("%2.1f",$delta));
        } elsif (defined $self->total()) {
            $delta = ($self->total() + $msgscore) / (1 + $self->count()) - $msgscore;

            $pms->set_tag('TXREP_'.$tag_id,             sprintf("%2.1f",$delta));
            if (defined $meanrep) {
                $pms->set_tag('TXREP_'.$tag_id.'_MEAN', sprintf("%2.1f", $meanrep));
            }
            $pms->set_tag('TXREP_'.$tag_id.'_COUNT',    sprintf("%2.1f", $self->count()));
            $pms->set_tag('TXREP_'.$tag_id.'_PRESCORE', sprintf("%2.1f", $pms->{score}));
        } else {
            $pms->set_tag('TXREP_'.$tag_id.'_UNKNOWN', 1);
        }
        dbg("TxRep: reputation: %s, count: %d, weight: %.1f, delta: %.3f, $tag_id: %s",
            defined $meanrep? sprintf("%.3f",$meanrep) : 'none',
            $self->count()      || 0,
            $weight             || 0,
            $delta              || 0,
            $id                 || 'none'
        );
    }
    $timer = $self->{main}->time_method('update_txrep_'.lc($key));
    if (defined $msgscore) {
        if ($self->{forgetting}) {              # forgetting a message score
            $self->remove_score($msgscore);     # remove the given score and decrement the count
            if ($key eq 'MSG_ID') {             # remove the message ID score completely
                $self->{checker}->remove_entry($self->{entry});
            }
        } else {
            $self->add_score($msgscore);        # add the score and increment the count
            if ($self->{learning} && $key eq 'MSG_ID' && $self->count() eq 1) {
                $self->add_score($msgscore);    # increasing the count by 1 at a learned score (count=2)
            }                                   # it can be distinguished from a scanned score (count=1)
        }
    } elsif (defined $found && $self->{forgetting} && $key eq 'MSG_ID') {
        $self->{checker}->remove_entry($self->{entry}); #forgetting the message ID
    }
  }
  if (defined $storage) {$self->{checker} = $self->{default_storage};}

  return ($weight || 0) * ($delta || 0);
}



#--------------------------------------------------------------------------
# Database handler subroutines
#--------------------------------------------------------------------------

###########################################################################
sub count {my $self=shift;  return (defined $self->{checker})? $self->{entry}->{count}    : undef;}
sub total {my $self=shift;  return (defined $self->{checker})? $self->{entry}->{totscore} : undef;}
###########################################################################


###########################################################################
sub get_sender {
###########################################################################
  my ($self, $addr, $origip, $signedby) = @_;

  return unless (defined $self->{checker});

  my $fulladdr   = $self->pack_addr($addr, $origip);
  my $entry      = $self->{checker}->get_addr_entry($fulladdr, $signedby);
  $self->{entry} = $entry;
  $origip        = $origip || 'none';

  if ($entry->{count}<0 || $entry->{count}=~/^(nan|)$/ || $entry->{totscore}=~/^(nan|)$/) {
    warn "TxRep: resetting bad data for ($addr, $origip), count: $entry->{count}, totscore: $entry->{totscore}\n";
    $self->{entry}->{count} = $self->{entry}->{totscore} = 0;
  }
  return $self->{entry}->{count};
}


###########################################################################
sub add_score {
###########################################################################
  my ($self,$score) = @_;

  return unless (defined $self->{checker});       # no factory defined; we can't check

  if ($score != $score) {
    warn "TxRep: attempt to add a $score to TxRep entry ignored\n";
    return;                                       # don't try to add a NaN
  }
  $self->{entry}->{count} ||= 0;

  # performing the dilution aging correction
  if (defined $self->total() && defined $self->count() && defined $self->{txrep_dilution_factor}) {
    my $diluted_total =
        ($self->count() + 1) *
        ($self->{txrep_dilution_factor} * $self->total() + $score) /
        ($self->{txrep_dilution_factor} * $self->count() + 1);
    my $corrected_score = $diluted_total - $self->total();
    $self->{checker}->add_score($self->{entry}, $corrected_score);
  } else {
    $self->{checker}->add_score($self->{entry}, $score);
  }
}



###########################################################################
sub remove_score {
###########################################################################
  my ($self,$score) = @_;

  return unless (defined $self->{checker});       # no factory defined; we can't check

  if ($score != $score) {                               # don't try to add a NaN
    warn "TxRep: attempt to add a $score to TxRep entry ignored\n";
    return;
  }
  # no reversal dilution aging correction (not easily possible),
  # just removing the original message score
  if ($self->{entry}->{count} > 2)
        {$self->{entry}->{count} -= 2;}
  else  {$self->{entry}->{count}  = 0;}
  # substract 2, and add a score; hence decrementing by 1
  $self->{checker}->add_score($self->{entry}, -1*$score);
}



###########################################################################
sub modify_reputation {
###########################################################################
  my ($self, $addr, $score, $signedby) = @_;

  return unless (defined $self->{checker});       # no factory defined; we can't check
  my $fulladdr = $self->pack_addr($addr, undef);
  my $entry    = $self->{checker}->get_addr_entry($fulladdr, $signedby);

  # remove any old entries (will remove per-ip entries as well)
  # always call this regardless, as the current entry may have 0
  # scores, but the per-ip one may have more
  $self->{checker}->remove_entry($entry);

  # remove address only, no new score to add if score NaN or undef
  if (defined $score && $score==$score) {
    # else add score. get a new entry first
    $entry = $self->{checker}->get_addr_entry($fulladdr, $signedby);
    $self->{checker}->add_score($entry, $score);
  }
  return 1;
}


# connecting the primary and the secondary storage; needed only on the first run
# (this can't be in the constructor, since the settings are not available there)
###########################################################################
sub open_storages {
###########################################################################
  my $self = shift;

  return 1 unless (!defined $self->{default_storage});

  my $factory;
  if ($self->{main}->{pers_addr_list_factory}) {
    $factory = $self->{main}->{pers_addr_list_factory};
  } else {
    my $type = $self->{conf}->{txrep_factory};
    if ($type =~ /^([_A-Za-z0-9:]+)$/) {
        $type = untaint_var($type);
        eval 'require    '.$type.';
            $factory = '.$type.'->new();
            1;'
        or do {
            my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
            warn "TxRep: $eval_stat\n";
            undef $factory;
        };
        $self->{main}->set_persistent_address_list_factory($factory) if $factory;
    } else {warn "TxRep: illegal factory setting\n";}
  }
  if (defined $factory) {
    $self->{checker} = $self->{default_storage} = $factory->new_checker($self->{main});

    if ($self->{conf}->{txrep_user2global_ratio} && !defined $self->{global_storage}) {
	# hack to handle the BDB and SQL factory types of the storage object
	# TODO: add an a method to the handler class instead
	my ($storage_type, $is_global);
	
	if (ref($factory) =~ /SQLasedAddrList/) {
	    $is_global    = defined $self->{conf}->{user_awl_sql_override_username};
	    $storage_type = 'SQL';
	    if ($is_global && $self->{conf}->{user_awl_sql_override_username} eq $self->{main}->{username}) {
		# skip double storage if current user same as the global override
		$self->{user_storage} = $self->{global_storage} = $self->{default_storage};
	    }
	} elsif (ref($factory) =~ /DBBasedAddrList/) {
	    $is_global    = $self->{conf}->{auto_whitelist_path} !~ /__userstate__/;
	    $storage_type = 'DB';
	}
	if (!defined $self->{global_storage}) {
	    my $sql_override_orig = $self->{conf}->{user_awl_sql_override_username};
	    my $awl_path_orig     = $self->{conf}->{auto_whitelist_path};
	    if ($is_global) {
		$self->{conf}->{user_awl_sql_override_username} = '';
		$self->{conf}->{auto_whitelist_path}            = '__userstate__/tx-reputation';
		$self->{global_storage} = $self->{default_storage};
		$self->{user_storage}   = $factory->new_checker($self->{main});
	    } else {
		$self->{conf}->{user_awl_sql_override_username} = 'GLOBAL';
		$self->{conf}->{auto_whitelist_path}            = '__local_state_dir__/tx-reputation';
		$self->{global_storage} = $factory->new_checker($self->{main});
		$self->{user_storage}   = $self->{default_storage};
	    }
	    $self->{conf}->{user_awl_sql_override_username} = $sql_override_orig;
	    $self->{conf}->{auto_whitelist_path}            = $awl_path_orig;
	
	    # Another ugly hack to find out whether the user differs from
	    # the global one. We need to add a method to the factory handlers
	    if ($storage_type eq 'DB' && 
		$self->{user_storage}->{locked_file} eq $self->{global_storage}->{locked_file}) {
		if ($is_global) 
		     {$self->{global_storage}->finish();}
		else {$self->{user_storage}->finish();}
		$self->{user_storage} = $self->{global_storage} = $self->{default_storage};
	    }
	}
    }
  } else {
    $self->{user_storage} = $self->{global_storage} = $self->{checker} = $self->{default_storage} = undef;
    warn("TxRep: could not open storages, quitting!\n");
    return 0;
  }
  return 1;
}


###########################################################################
sub finish {
###########################################################################
  my $self = shift;

  return unless (defined $self->{checker});       # no factory defined; we can't check

  if ($self->{conf}->{txrep_user2global_ratio} && defined $self->{user_storage} && ($self->{user_storage} != $self->{global_storage})) {
    $self->{user_storage}->finish();
    $self->{global_storage}->finish();
    $self->{user_storage}   = undef;
    $self->{global_storage} = undef;
  } elsif (defined $self->{default_storage}) {
    $self->{default_storage}->finish();
    $self->{default_storage} = $self->{checker} = undef;
  }
 $self->{factory} = undef;
}


###########################################################################
sub ip_to_awl_key {
###########################################################################
  my ($self, $origip) = @_;

  my $result;
  local $1;
  if (!defined $origip) {
    # could not find an IP address to use
  } elsif ($origip =~ /^ (\d{1,3} \. \d{1,3}) \. \d{1,3} \. \d{1,3} $/xs) {
    my $mask_len = $self->{ipv4_mask_len};
    $mask_len = 16  if !defined $mask_len;
    # handle the default and easy cases manually
    if    ($mask_len == 32) {$result = $origip;}
    elsif ($mask_len == 16) {$result = $1;}
    else {
      my $origip_obj = NetAddr::IP->new($origip . '/' . $mask_len);
      if (!defined $origip_obj) {                       # invalid IPv4 address
        dbg("TxRep: bad IPv4 address $origip");
      } else {
        $result =        $origip_obj->network->addr;
        $result =~s/(\.0){1,3}\z//;                     # truncate zero tail
      }
    }
  } elsif ($origip =~ /:/ &&                            # triage
           $origip =~
           /^ [0-9a-f]{0,4} (?: : [0-9a-f]{0,4} | \. [0-9]{1,3} ){2,9} $/xsi) {
    # looks like an IPv6 address
    my $mask_len = $self->{ipv6_mask_len};
    $mask_len = 48  if !defined $mask_len;
    my $origip_obj = NetAddr::IP->new6($origip . '/' . $mask_len);
    if (!defined $origip_obj) {                         # invalid IPv6 address
      dbg("TxRep: bad IPv6 address $origip");
    } else {
      $result = $origip_obj->network->full6;            # string in a canonical form
      $result =~ s/(:0000){1,7}\z/::/;                  # compress zero tail
    }
  } else {
    dbg("TxRep: bad IP address $origip");
  }
  if (defined $result && length($result) > 39) {        # just in case, keep under
    $result = substr($result,0,39);                     # the awl.ip field size
  }
# if (defined $result) {dbg("TxRep: IP masking %s -> %s", $origip || '?', $result || '?');}
  return $result;
}


###########################################################################
sub pack_addr {
###########################################################################
  my ($self, $addr, $origip) = @_;

  $addr = lc $addr;
  $addr =~ s/[\000\;\'\"\!\|]/_/gs;                     # paranoia

  if ( defined $origip) {$origip = $self->ip_to_awl_key($origip);}
  if (!defined $origip) {$origip = 'none';}
  return $addr . "|ip=" . $origip;
}



# -------------------------------------------------------------------------
=head1 LEARNING SPAM / HAM

When SpamAssassin is told to learn (or relearn) a given message as spam or
ham, all reputations relevant to the message (email, email_ip, domain, ip, helo)
in both global and user storages will be updated using the C<txrep_learn_penalty>
respectively the C<rxrep_learn_bonus> values. The new reputation of given sender
property (email, domain,...) will be the respective result of one of the following
formulas:

   new_reputation = old_reputation + learn_penalty
   new_reputation = old_reputation - learn_bonus

The TxRep plugin currently does track each message individually, hence it
does not detect when you learn the message repeatedly. It will add/subtract
the penalty/bonus score each time the message is fed to the spam learner.

=cut
######################################################### plugin hook #####
sub learner_new {
###########################################################################
  my ($self) = @_;

  $self->{txKeepStoreTied} = 1;
  return $self;
}


######################################################### plugin hook #####
sub autolearn {
###########################################################################
  my ($self, $params) = @_;

  $self->{last_pms} = $params->{permsgstatus};
  return $self->{autolearn} = 1;
}


######################################################### plugin hook #####
sub learn_message {
###########################################################################
  my ($self, $params) = @_;
  return 0 unless (defined $params->{isspam});

  dbg("TxRep: learning a message");
  my $pms = ($self->{last_pms})? $self->{last_pms} : Mail::SpamAssassin::PerMsgStatus->new($self->{main}, $params->{msg});
  if (!defined $pms->{relays_internal} && !defined $pms->{relays_external}) {
    $pms->extract_message_metadata();
  }

  if ($params->{isspam})
        {$self->{learning} =      $self->{conf}->{txrep_learn_penalty};}
  else  {$self->{learning} = -1 * $self->{conf}->{txrep_learn_bonus};}

  my $ret = !$self->{learning} || $self->check_senders_reputation($pms);
  $self->{learning} = undef;
  return $ret;
}


######################################################### plugin hook #####
sub forget_message {
###########################################################################
  my ($self, $params) = @_;
  return 0 unless ($self->{conf}->{use_txrep});
  my $pms = ($self->{last_pms})? $self->{last_pms} : Mail::SpamAssassin::PerMsgStatus->new($self->{main}, $params->{msg});

  dbg("TxRep: forgetting a message");
  $self->{forgetting} = 1;
  my $ret = $self->check_senders_reputation($pms);
  $self->{forgetting} = undef;
  return $ret;
}


######################################################### plugin hook #####
sub learner_expire_old_training {
###########################################################################
  my ($self, $params) = @_;
  return 0 unless ($self->{conf}->{use_txrep} && $self->{conf}->{txrep_expiry_days});

  dbg("TxRep: expiry not implemented yet");
#  dbg("TxRep: expiry starting");
#  my $timer = $self->{main}->time_method("expire_bayes");
#  $self->{store}->expire_old_tokens($params);
#  dbg("TxRep: expiry completed");
}


######################################################### plugin hook #####
sub learner_close {
###########################################################################
  my ($self, $params) = @_;
  my $quiet = $params->{quiet};
  return 0 unless ($self->{conf}->{use_txrep});

  $self->{txKeepStoreTied} = undef;
  $self->finish();
  dbg("TxRep: learner_close");
}


# -------------------------------------------------------------------------
=head1 OPTIMIZING TXREP

TxRep can be optimized for speed and simplicity, or for the precision in
assigning the reputation scores.

First of all TxRep can be quickly disabled and re-enabled through the option
L</C<use_txrep>>. It can be done globally, or individually in each respective
C<user_prefs>. Disabling TxRep will not destroy the database, so it can be
re-enabled any time later again.

On many systems, SQL-based storage may perform faster than the default
Berkeley DB storage, so you should consider setting it up. See the section
L</SQL-BASED STORAGE> for instructions.

Then there are multiple settings that can reduce the number of records stored
in the database, hence reducing the size of the storage, and also the processing
time:

1. Setting L</C<txrep_user2global_ratio>> to zero will disable the dual storage,
halving so the disk space requirements, and the processing times of this plugin.

2. You can disable all but one of the L<REPUTATION WEIGHTS>. The EMAIL_IP is
the most specific option, so it is the most likely choice in such case, but you
could base the reputation system on any of the remaining scores. Each of the
enabled reputations adds a new entry to the database for each new identificator.
So while for example the number of recorded and scored domains may be big, the
number of stored IP addresses will be probably higher, and would require more
space in the storage.

3. Disabling the L</C<txrep_track_messages>> avoids storing a separate entry
for every scanned message, hence also reducing the disk space requirements, and
the processing time.

4. Disabling the option L</C<txrep_autolearn>> will save the processing time
at messages that trigger the auto-learning process.

5. Disabling L</C<txrep_whitelist_out>> will reduce the processing time at
outbound connections.

6. Keeping the option L</C<auto_whitelist_distinguish_signed>> enabled may help
slightly reducing the size of the database, because at signed messages, the
originating IP address is ignored, hence no additional database entries are
needed for each separate IP address (resp. a masked block of IP addresses).


Since TxRep reuses the storage architecture of the former AWL plugin, for
initializing the SQL storage, the same instructions apply also to TxRep.
Although the old AWL table can be reused for TxRep, by default TxRep expects
the SQL table to be named "txrep".

To install a new SQL table for TxRep, run the appropriate SQL file for your
system under the /sql directory.

If you get a syntax error at an older version of MySQL, use TYPE=MyISAM
instead of ENGINE=MyISAM at the end of the command. You can also use other
types of ENGINE (depending on what is available on your system). For example
MEMORY engine stores the entire table in the server memory, achieving
performance similar to Redis. You would need to care about the replication
of the RAM table to disk through a cronjob, to avoid loss of data at reboot.
The InnoDB engine is used by default, offering high scalability (database
size and concurence of accesses). In conjunction with a high value of
innodb_buffer_pool or with the memcached plugin (MySQL v5.6+) it can also
offer performance comparable to Redis.

=cut

1;
