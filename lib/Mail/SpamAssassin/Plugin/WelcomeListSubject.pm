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

Mail::SpamAssassin::Plugin::WelcomeListSubject - welcomelist by Subject header

=head1 SYNOPSIS

 loadplugin Mail::SpamAssassin::Plugin::WelcomeListSubject

 header SUBJECT_IN_WELCOMELIST eval:check_subject_in_welcomelist()
 header SUBJECT_IN_BLOCKLIST eval:check_subject_in_blocklist()

 score SUBJECT_IN_WELCOMELIST -100
 score SUBJECT_IN_BLOCKLIST 100

 welcomelist_subject [Bug *]
 blocklist_subject Make Money Fast

=head1 DESCRIPTION

This SpamAssassin plugin module provides eval tests for welcomelisting and
blocklisting particular strings in the Subject header. String will match
anywhere in the subject. The value for welcomelist_subject or blocklist_subject
are strings which may contain file -glob -style patterns, similar to the
other welcomelist_* config options. Note that each subject/string must be a
separate *_subject command, all whitespace is included in the string.

=cut

package Mail::SpamAssassin::Plugin::WelcomeListSubject;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Util qw(compile_regexp);
use strict;
use warnings;
# use bytes;
use re 'taint';

our @ISA = qw(Mail::SpamAssassin::Plugin);

# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->register_eval_rule ("check_subject_in_welcomelist", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule ("check_subject_in_whitelist", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS); # removed in 4.1
  $self->register_eval_rule ("check_subject_in_blocklist", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
  $self->register_eval_rule ("check_subject_in_blacklist", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS); # removed in 4.1

  $self->set_config($mailsaobject->{conf});

  return $self;
}

sub set_config {
  my ($self, $conf) = @_;

  my @cmds;

  push(@cmds, {
	       setting => 'welcomelist_subject',
	       aliases => ['whitelist_subject'], # removed in 4.1
	       default => {},
               type => $Mail::SpamAssassin::Conf::CONF_TYPE_ADDRLIST,
	       code => sub {
		 my ($self, $key, $value, $line) = @_;

		 $value = lc $value;
		 my $re = $value;
		 $re =~ s/([^\*\?_a-zA-Z0-9])/\\$1/g;        # escape any possible metachars
		 $re =~ tr/?/./;                             # "?" -> "."
                 $re =~ s/\*+/\.\*/g;                        # "*" -> "any string"
                 my ($rec, $err) = compile_regexp($re, 0);
                 if (!$rec) {
                   warn "could not compile $key '$value': $err";
                   return;
                 }
 		 $conf->{$key}->{$value} = $rec;
	       }});

  push(@cmds, {
	       setting => 'blocklist_subject',
	       aliases => ['blacklist_subject'], # removed in 4.1
	       default => {},
               type => $Mail::SpamAssassin::Conf::CONF_TYPE_ADDRLIST,
	       code => sub {
		 my ($self, $key, $value, $line) = @_;

		 $value = lc $value;
		 my $re = $value;
		 $re =~ s/([^\*\?_a-zA-Z0-9])/\\$1/g;        # escape any possible metachars
		 $re =~ tr/?/./;                             # "?" -> "."
                 $re =~ s/\*+/\.\*/g;                        # "*" -> "any string"
                 my ($rec, $err) = compile_regexp($re, 0);
                 if (!$rec) {
                   warn "could not compile $key '$value': $err";
                   return;
                 }
 		 $conf->{$key}->{$value} = $rec;
	       }});

  $conf->{parser}->register_commands(\@cmds);
}

sub check_subject_in_welcomelist {
  my ($self, $permsgstatus) = @_;

  my $subject = $permsgstatus->get('Subject');

  return 0 unless $subject ne '';

  return $self->_check_subject($permsgstatus->{conf}->{welcomelist_subject}, $subject);
}
*check_subject_in_whitelist = \&check_subject_in_welcomelist; # removed in 4.1

sub check_subject_in_blocklist {
  my ($self, $permsgstatus) = @_;

  my $subject = $permsgstatus->get('Subject');

  return 0 unless $subject ne '';

  return $self->_check_subject($permsgstatus->{conf}->{blocklist_subject}, $subject);
}
*check_subject_in_blacklist = \&check_subject_in_blocklist; # removed in 4.1

sub _check_subject {
  my ($self, $list, $subject) = @_;

  $subject = lc $subject;

  return 1 if defined($list->{$subject});

  foreach my $regexp (values %{$list}) {
    if ($subject =~ $regexp) {
      return 1;
    }
  }

  return 0;
}

1;
