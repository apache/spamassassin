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

Mail::SpamAssassin::Plugin::Pyzor - perform Pyzor check of messages

=head1 SYNOPSIS

  loadplugin     Mail::SpamAssassin::Plugin::Pyzor

=head1 DESCRIPTION

Pyzor is a collaborative, networked system to detect and block spam
using identifying digests of messages.

See http://pyzor.sourceforge.net/ for more information about Pyzor.

=cut

package Mail::SpamAssassin::Plugin::Pyzor;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Timeout;
use strict;
use warnings;
use bytes;

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

sub new {
  my $class = shift;
  my $mailsaobject = shift;

  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  # are network tests enabled?
  if ($mailsaobject->{local_tests_only}) {
    $self->{pyzor_available} = 0;
    dbg("pyzor: local tests only, disabling Pyzor");
  }
  else {
    $self->{pyzor_available} = 1;
    dbg("pyzor: network tests on, attempting Pyzor");
  }

  $self->register_eval_rule("check_pyzor");

  $self->set_config($mailsaobject->{conf});

  return $self;
}

sub set_config {
  my ($self, $conf) = @_;
  my @cmds = ();

=head1 USER OPTIONS

=over 4

=item use_pyzor (0|1)		(default: 1)

Whether to use Pyzor, if it is available.

=cut

  push (@cmds, {
    setting => 'use_pyzor',
    default => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL
  });

=item pyzor_max NUMBER		(default: 5)

This option sets how often a message's body checksum must have been
reported to the Pyzor server before SpamAssassin will consider the Pyzor
check as matched.

As most clients should not be auto-reporting these checksums, you should
set this to a relatively low value, e.g. C<5>.

=cut

  push (@cmds, {
    setting => 'pyzor_max',
    default => 5,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });

=back

=head1 ADMINISTRATOR OPTIONS

=over 4

=item pyzor_timeout n		(default: 3.5)

How many seconds you wait for Pyzor to complete, before scanning continues
without the Pyzor results.

You can configure Pyzor to have its own per-server timeout.  Set this
plugin's timeout with that in mind.  This plugin's timeout is a maximum
ceiling.  If Pyzor takes longer than this to complete its communication
with all servers, no results are used by SpamAssassin.

Pyzor servers do not yet synchronize their servers, so it can be
beneficial to check and report to more than one.  See the pyzor-users
mailing list for alternate servers that are not published via
'pyzor discover'.

If you are using multiple Pyzor servers, a good rule of thumb would be to
set the SpamAssassin plugin's timeout to be the same or just a bit more
than the per-server Pyzor timeout (e.g., 3.5 and 2 for two Pyzor servers).
If more than one of your Pyzor servers is always timing out, consider
removing one of them.

=cut

  push (@cmds, {
    setting => 'pyzor_timeout',
    is_admin => 1,
    default => 3.5,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC
  });

=item pyzor_options options

Specify additional options to the pyzor(1) command. Please note that only
characters in the range [0-9A-Za-z ,._/-] are allowed for security reasons.

=cut

  push (@cmds, {
    setting => 'pyzor_options',
    is_admin => 1,
    default => '',
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if ($value !~ m{^([0-9A-Za-z ,._/-]+)$}) {
	return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      $self->{pyzor_options} = $1;
    }
  });

=item pyzor_path STRING

This option tells SpamAssassin specifically where to find the C<pyzor>
client instead of relying on SpamAssassin to find it in the current
PATH.  Note that if I<taint mode> is enabled in the Perl interpreter,
you should use this, as the current PATH will have been cleared.

=cut

  push (@cmds, {
    setting => 'pyzor_path',
    is_admin => 1,
    default => undef,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if (!defined $value || !length $value) {
	return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      $value = Mail::SpamAssassin::Util::untaint_file_path($value);
      if (!-x $value) {
	info("config: pyzor_path \"$value\" isn't an executable");
	return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }

      $self->{pyzor_path} = $value;
    }
  });

  $conf->{parser}->register_commands(\@cmds);
}

sub is_pyzor_available {
  my ($self) = @_;

  my $pyzor = $self->{main}->{conf}->{pyzor_path} || '';
  unless ($pyzor) {
    $pyzor = Mail::SpamAssassin::Util::find_executable_in_env_path('pyzor');
  }
  unless ($pyzor && -x $pyzor) {
    dbg("pyzor: pyzor is not available: no pyzor executable found");
    return 0;
  }

  # remember any found pyzor
  $self->{main}->{conf}->{pyzor_path} = $pyzor;

  dbg("pyzor: pyzor is available: " . $self->{main}->{conf}->{pyzor_path});
  return 1;
}

sub get_pyzor_interface {
  my ($self) = @_;

  if (!$self->{main}->{conf}->{use_pyzor}) {
    dbg("pyzor: use_pyzor option not enabled, disabling Pyzor");
    $self->{pyzor_interface} = "disabled";
    $self->{pyzor_available} = 0;
  }
  elsif ($self->is_pyzor_available()) {
    $self->{pyzor_interface} = "pyzor";
    $self->{pyzor_available} = 1;
  }
  else {
    dbg("pyzor: no pyzor found, disabling Pyzor");
    $self->{pyzor_available} = 0;
  }
}

sub check_pyzor {
  my ($self, $permsgstatus, $full) = @_;

  # initialize valid tags
  $permsgstatus->{tag_data}->{PYZOR} = "";

  $self->get_pyzor_interface();
  return 0 unless $self->{pyzor_available};

  return $self->pyzor_lookup($permsgstatus, $full);
}

sub pyzor_lookup {
  my ($self, $permsgstatus, $fulltext) = @_;
  my @response;
  my $pyzor_count;
  my $pyzor_whitelisted;
  my $timeout = $self->{main}->{conf}->{pyzor_timeout};

  $pyzor_count = 0;
  $pyzor_whitelisted = 0;
  my $pid;

  # use a temp file here -- open2() is unreliable, buffering-wise, under spamd
  my $tmpf = $permsgstatus->create_fulltext_tmpfile($fulltext);

  # note: not really tainted, this came from system configuration file
  my $path = Mail::SpamAssassin::Util::untaint_file_path($self->{main}->{conf}->{pyzor_path});

  my $opts = $self->{main}->{conf}->{pyzor_options} || '';

  $permsgstatus->enter_helper_run_mode();

  my $timer = Mail::SpamAssassin::Timeout->new({ secs => $timeout });
  my $err = $timer->run_and_catch(sub {

    local $SIG{PIPE} = sub { die "__brokenpipe__ignore__\n" };
 
    dbg("pyzor: opening pipe: " . join(' ', $path, $opts, "check", "< $tmpf"));

    $pid = Mail::SpamAssassin::Util::helper_app_pipe_open(*PYZOR,
	$tmpf, 1, $path, split(' ', $opts), "check");
    $pid or die "$!\n";

    @response = <PYZOR>;
    close PYZOR
      or dbg(sprintf("pyzor: [%s] finished: %s exit=0x%04x",$pid,$!,$?));

    if (!@response) {
      # this exact string is needed below
      die("no response\n");	# yes, this is possible
    }
    map { chomp } @response;
    dbg("pyzor: got response: " . join("\\n", @response));

    if ($response[0] =~ /^Traceback/) {
      # this exact string is needed below
      die("internal error\n");
    }

  });

  if (defined(fileno(*PYZOR))) {  # still open
    if ($pid) {
      if (kill('TERM',$pid)) { dbg("pyzor: killed stale helper [$pid]") }
      else { dbg("pyzor: killing helper application [$pid] failed: $!") }
    }
    close PYZOR
      or dbg(sprintf("pyzor: [%s] terminated: %s exit=0x%04x",$pid,$!,$?));
  }
  $permsgstatus->leave_helper_run_mode();

  if ($timer->timed_out()) {
    dbg("pyzor: check timed out after $timeout seconds");
    return 0;
  }

  if ($err) {
    chomp $err;
    if ($err eq "__brokenpipe__ignore__") {
      dbg("pyzor: check failed: broken pipe");
    } elsif ($err eq "no response") {
      dbg("pyzor: check failed: no response");
    } else {
      warn("pyzor: check failed: $err\n");
    }
    return 0;
  }

  foreach my $one_response (@response) {
    # this regexp is intended to be a little bit forgiving
    if ($one_response =~ /^\S+\t.*?\t(\d+)\t(\d+)\s*$/) {
      # until pyzor servers can sync their DBs,
      # sum counts obtained from all servers
      $pyzor_whitelisted += $2+0;
      $pyzor_count += $1+0;
    }
    else {
      # warn on failures to parse
      dbg("pyzor: failure to parse response \"$one_response\"");
    }
  }

  if ($pyzor_whitelisted) {
    $permsgstatus->{tag_data}->{PYZOR} = "Whitelisted.";
  }
  else {
    $permsgstatus->{tag_data}->{PYZOR} = "Reported $pyzor_count times.";
  }

  if ($pyzor_count >= $self->{main}->{conf}->{pyzor_max}) {
    dbg("pyzor: listed: COUNT=$pyzor_count/$self->{main}->{conf}->{pyzor_max} WHITELIST=$pyzor_whitelisted");
    return 1;
  }

  return 0;
}

sub plugin_report {
  my ($self, $options) = @_;

  return unless $self->{pyzor_available};
  return unless $self->{main}->{conf}->{use_pyzor};

  if (!$options->{report}->{options}->{dont_report_to_pyzor} && $self->is_pyzor_available())
  {
    # use temporary file: open2() is unreliable due to buffering under spamd
    my $tmpf = $options->{report}->create_fulltext_tmpfile($options->{text});
    if ($self->pyzor_report($options, $tmpf)) {
      $options->{report}->{report_available} = 1;
      info("reporter: spam reported to Pyzor");
      $options->{report}->{report_return} = 1;
    }
    else {
      info("reporter: could not report spam to Pyzor");
    }
    $options->{report}->delete_fulltext_tmpfile();
  }
}

sub pyzor_report {
  my ($self, $options, $tmpf) = @_;

  # note: not really tainted, this came from system configuration file
  my $path = Mail::SpamAssassin::Util::untaint_file_path($options->{report}->{conf}->{pyzor_path});

  my $opts = $options->{report}->{conf}->{pyzor_options} || '';
  my $timeout = $self->{main}->{conf}->{pyzor_timeout};

  $options->{report}->enter_helper_run_mode();

  my $timer = Mail::SpamAssassin::Timeout->new({ secs => $timeout });
  my $err = $timer->run_and_catch(sub {

    local $SIG{PIPE} = sub { die "__brokenpipe__ignore__\n" };

    dbg("pyzor: opening pipe: " . join(' ', $path, $opts, "report", "< $tmpf"));

    my $pid = Mail::SpamAssassin::Util::helper_app_pipe_open(*PYZOR,
	$tmpf, 1, $path, split(' ', $opts), "report");
    $pid or die "$!\n";

    my @ignored = <PYZOR>;
    $options->{report}->close_pipe_fh(\*PYZOR);

    waitpid ($pid, 0);
  });

  $options->{report}->leave_helper_run_mode();

  if ($timer->timed_out()) {
    dbg("reporter: pyzor report timed out after $timeout seconds");
    return 0;
  }

  if ($err) {
    chomp $err;
    if ($err eq '__brokenpipe__ignore__') {
      dbg("reporter: pyzor report failed: broken pipe");
    } else {
      warn("reporter: pyzor report failed: $err\n");
    }
    return 0;
  }

  return 1;
}

1;

=back

=cut
