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

Mail::SpamAssassin::Plugin::Razor2 - perform Razor check of messages

=head1 SYNOPSIS

  loadplugin     Mail::SpamAssassin::Plugin::Razor2

=head1 DESCRIPTION

Vipul's Razor is a distributed, collaborative, spam detection and
filtering network based on user submissions of spam.  Detection is done
with signatures that efficiently spot mutating spam content and user
input is validated through reputation assignments.

Note that Razor2 is disabled by default in C<init.pre> because it is not
available for unlimited free use.  It is currently free for personal
use, subject to capacity constraints.  See the Cloudmark SpamNet Service
Policy for more details.

See http://razor.sourceforge.net/ for more information about Razor.

=over 4

=cut

package Mail::SpamAssassin::Plugin::Razor2;

# Make the main dbg() accessible in our package w/o an extra function
*dbg=\&Mail::SpamAssassin::Plugin::dbg;
*info=\&Mail::SpamAssassin::Plugin::info;

use Mail::SpamAssassin::Plugin;
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

  # figure out if razor is even available or not ...
  $self->{razor2_available} = 0;
  if ($mailsaobject->{local_tests_only}) {
    dbg("razor2: local tests only, skipping Razor");
  }
  else {
    if (eval { require Razor2::Client::Agent; }) {
      $self->{razor2_available} = 1;
      dbg("razor2: razor2 is available, version " . $Razor2::Client::Version::VERSION . "\n");
    }
    else {
      dbg("razor2: razor2 is not available");
    }
  }

  $self->register_eval_rule("check_razor2");
  $self->register_eval_rule("check_razor2_range");

  $self->set_config($mailsaobject->{conf});

  return $self;
}

sub set_config {
  my ($self, $conf) = @_;
  my @cmds = ();

=item use_razor2 (0|1)		(default: 1)

Whether to use Razor2, if it is available.

=cut

  push(@cmds, {
    setting => 'use_razor2',
    default => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });

=item razor_timeout n		(default: 5)

How many seconds you wait for Razor to complete before you go on without
the results

=cut

  push(@cmds, {
    setting => 'razor_timeout',
    default => 5,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });

=item razor_config filename

Define the filename used to store Razor's configuration settings.
Currently this is left to Razor to decide.

=cut

  push(@cmds, {
    setting => 'razor_config',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
  });

  $conf->{parser}->register_commands(\@cmds);
}

sub razor2_access {
  my ($self, $fulltext, $type) = @_;
  my $timeout = $self->{main}->{conf}->{razor_timeout};
  my $return = 0;
  my @results = ();

  my $debug = $type eq 'check' ? 'razor2' : 'reporter';

  # razor also debugs to stdout. argh. fix it to stderr...
  if (Mail::SpamAssassin::dbg_check($debug)) {
    open(OLDOUT, ">&STDOUT");
    open(STDOUT, ">&STDERR");
  }

  Mail::SpamAssassin::PerMsgStatus::enter_helper_run_mode($self);
  my $oldalarm = 0;

  eval {
    local ($^W) = 0;    # argh, warnings in Razor

    local $SIG{ALRM} = sub { die "alarm\n" };
    $oldalarm = alarm $timeout;

    # everything's in the module!
    my $rc = Razor2::Client::Agent->new("razor-$type");

    if ($rc) {
      $rc->{opt} = {
	debug => Mail::SpamAssassin::dbg_check('+razor2'),
	foreground => 1,
	config => $self->{main}->{conf}->{razor_config}
      };
      # no facility prefix on this die
      $rc->do_conf() or die "$debug: " . $rc->errstr;

      # Razor2 requires authentication for reporting
      my $ident;
      if ($type ne 'check') {
	# no facility prefix on this die
	$ident = $rc->get_ident
	    or die("$type requires authentication");
      }

      my @msg = ($fulltext);
      # no facility prefix on this die
      my $objects = $rc->prepare_objects(\@msg)
	  or die "$debug: error in prepare_objects";
      unless ($rc->get_server_info()) {
	my $error = $rc->errprefix("$debug: spamassassin") || "$debug: razor2 had unknown error during get_server_info";
	die $error;
      }

      # let's reset the alarm since get_server_info() calls
      # nextserver() which calls discover() which very likely will
      # reset the alarm for us ... how polite.  :(
      alarm $timeout;

      # no facility prefix on this die
      my $sigs = $rc->compute_sigs($objects)
	  or die "$debug: error in compute_sigs";

      # if mail isn't whitelisted, check it out
      # see 'man razor-whitelist'
      if ($type ne 'check' || ! $rc->local_check($objects->[0])) {
	# provide a better error message when servers are unavailable,
	# than "Bad file descriptor Died".
	$rc->connect() or die "$debug: could not connect to any servers\n";

	# Talk to the Razor server and do work
	if ($type eq 'check') {
	  unless ($rc->check($objects)) {
	    my $error = $rc->errprefix("$debug: spamassassin") || "$debug: razor2 had unknown error during check";
	    die $error;
	  }
	}
	else {
	  unless ($rc->authenticate($ident)) {
	    my $error = $rc->errprefix("$debug: spamassassin") || "$debug: razor2 had unknown error during authenticate";
	    die $error;
	    }
	  unless ($rc->report($objects)) {
	    my $error = $rc->errprefix("$debug: spamassassin") || "$debug: razor2 had unknown error during report";
	    die $error;
	  }
	}

	unless ($rc->disconnect()) {
	  my $error = $rc->errprefix("$debug: spamassassin") || "$debug: razor2 had unknown error during disconnect";
	  die $error;
	}

	# if we got here, we're done doing remote stuff, abort the alert
	alarm 0;

	# Razor 2.14 says that if we get here, we did ok.
	$return = 1;

	# figure out if we have a log file we need to close...
	if (ref($rc->{logref}) && exists $rc->{logref}->{fd}) {
	  # the fd can be stdout or stderr, so we need to find out if it is
	  # so we don't close them by accident.  Note: we can't just
	  # undef the fd here (like the IO::Handle manpage says we can)
	  # because it won't actually close, unfortunately. :(
	  my $untie = 1;
	  foreach my $log (*STDOUT{IO}, *STDERR{IO}) {
	    if ($log == $rc->{logref}->{fd}) {
	      $untie = 0;
	      last;
	    }
	  }
	  close $rc->{logref}->{fd} if ($untie);
	}

	if ($type eq 'check') {
	  # so $objects->[0] is the first (only) message, and ->{spam} is a general yes/no
	  push(@results, { result => $objects->[0]->{spam} });

	  # great for debugging, but leave this off!
	  #use Data::Dumper;
	  #print Dumper($objects),"\n";

	  # ->{p} is for each part of the message
	  # so go through each part, taking the highest cf we find
	  # of any part that isn't contested (ct).  This helps avoid false
	  # positives.  equals logic_method 4.
	  #
	  # razor-agents < 2.14 have a different object format, so we now support both.
	  # $objects->[0]->{resp} vs $objects->[0]->{p}->[part #]->{resp}
	  my $part = 0;
	  my $arrayref = $objects->[0]->{p} || $objects;
	  if (defined $arrayref) {
	    foreach my $cf (@{$arrayref}) {
	      if (exists $cf->{resp}) {
		for (my $response=0; $response<@{$cf->{resp}}; $response++) {
		  my $tmp = $cf->{resp}->[$response];
		  my $tmpcf = $tmp->{cf}; # Part confidence
		  my $tmpct = $tmp->{ct}; # Part contested?
		  my $engine = $cf->{sent}->[$response]->{e};

		  # These should always be set, but just in case ...
		  $tmpcf = 0 unless defined $tmpcf;
		  $tmpct = 0 unless defined $tmpct;
		  $engine = 0 unless defined $engine;

		  push(@results,
		       { part => $part, engine => $engine, contested => $tmpct, confidence => $tmpcf });
		}
	      }
	      else {
		push(@results, { part => $part, noresponse => 1 });
	      }
	      $part++;
	    }
	  }
	  else {
	    # If we have some new $objects format that isn't close to
	    # the current razor-agents 2.x version, we won't FP but we
	    # should alert in debug.
	    dbg("$debug: it looks like the internal Razor object has changed format!");
	  }
	}
      }
    }
    else {
      warn "$debug: undefined Razor2::Client::Agent\n";
    }
  
    # note: this may be a double-reset.  not a big deal though; the
    # result should only be the extension of a preexisting timeout
    # by < 1 sec.
    alarm $oldalarm;
  };

  my $err = $@;

  if ($err) {
    alarm $oldalarm;    # just in case
    chomp $err;
    if ($err =~ /alarm/) {
      dbg("$debug: razor2 $type timed out after $timeout seconds");
    } elsif ($err =~ /(?:could not connect|network is unreachable)/) {
      # make this a dbg(); SpamAssassin will still continue,
      # but without Razor checking.  otherwise there may be
      # DSNs and errors in syslog etc., yuck
      dbg("$debug: razor2 $type could not connect to any servers");
    } elsif ($err =~ /timeout/i) {
      dbg("$debug: razor2 $type timed out connecting to servers");
    } else {
      warn("$debug: razor2 $type failed: $! $err");
    }
  }

  # work around serious brain damage in Razor2 (constant seed)
  srand;

  Mail::SpamAssassin::PerMsgStatus::leave_helper_run_mode($self);

  # razor also debugs to stdout. argh. fix it to stderr...
  if (Mail::SpamAssassin::dbg_check($debug)) {
    open(STDOUT, ">&OLDOUT");
    close OLDOUT;
  }

  return wantarray ? ($return, @results) : $return;
}

sub plugin_report {
  my ($self, $options) = @_;

  return unless $self->{razor2_available};
  return if $self->{main}->{local_tests_only};
  return unless $self->{main}->{conf}->{use_razor2};
  return if $options->{report}->{options}->{dont_report_to_razor};

  if ($self->razor2_access($options->{text}, 'report')) {
    $options->{report}->{report_available} = 1;
    info('reporter: spam reported to Razor');
    $options->{report}->{report_return} = 1;
  }
  else {
    info('reporter: could not report spam to Razor');
  }
}

sub plugin_revoke {
  my ($self, $options) = @_;

  return unless $self->{razor2_available};
  return if $self->{main}->{local_tests_only};
  return unless $self->{main}->{conf}->{use_razor2};
  return if $options->{revoke}->{options}->{dont_report_to_razor};

  if ($self->razor2_access($options->{text}, 'revoke')) {
    $options->{revoke}->{revoke_available} = 1;
    dbg('reporter: spam revoked from Razor');
    $options->{revoke}->{revoke_return} = 1;
  }
  else {
    dbg('reporter: could not revoke spam from Razor');
  }
}

sub check_razor2 {
  my ($self, $permsgstatus, $full) = @_;

  return $permsgstatus->{razor2_result} if (defined $permsgstatus->{razor2_result});
  $permsgstatus->{razor2_result} = 0;
  $permsgstatus->{razor2_cf_score} = 0;

  return unless $self->{razor2_available};
  return unless $self->{main}->{conf}->{use_razor2};

  my $return;
  my @results = ();

  # TODO: check for cache header, set results appropriately

  # do it this way to make it easier to get out the results later from the
  # netcache plugin
  ($return, @results) = $self->razor2_access($full, 'check');
  $self->{main}->call_plugins ('process_razor_result',
  	{ results => \@results, permsgstatus => $permsgstatus }
  );

  foreach my $result (@results) {
    if (exists $result->{result}) {
      $permsgstatus->{razor2_result} = $result->{result} if $result->{result};
    }
    elsif ($result->{noresponse}) {
      dbg('razor2: part=' . $result->{part} . ' noresponse');
    }
    else {
      dbg('razor2: part=' . $result->{part} .
        ' engine=' .  $result->{engine} .
	' contested=' . $result->{contested} .
	' confidence=' . $result->{confidence});

      next if $result->{contested};
      if ($result->{confidence} > $permsgstatus->{razor2_cf_score}) {
        $permsgstatus->{razor2_cf_score} = $result->{confidence};
      }
    }
  }

  dbg("razor2: results: spam? " . $permsgstatus->{razor2_result} .
    "  highest cf score: " . $permsgstatus->{razor2_cf_score} . "\n");

  return $permsgstatus->{razor2_result};
}

# Check the cf value of a given message and return if it's within the
# given range
sub check_razor2_range {
  my ($self, $permsgstatus, $body, $min, $max) = @_;

  # If Razor2 isn't available, or the general test is disabled, don't
  # continue.
  return unless $self->{razor2_available};
  return unless $self->{main}->{conf}->{use_razor2};
  return unless $self->{main}->{conf}->{scores}->{'RAZOR2_CHECK'};

  # If Razor2 hasn't been checked yet, go ahead and run it.
  unless (defined $permsgstatus->{razor2_result}) {
    $self->check_razor2($permsgstatus, $body);
  }

  if ($permsgstatus->{razor2_cf_score} >= $min && $permsgstatus->{razor2_cf_score} <= $max) {
    $permsgstatus->test_log(sprintf("cf: %3d", $permsgstatus->{razor2_cf_score}));
    return 1;
  }

  return;
}

1;
