=head1 NAME

Mail::SpamAssassin::Plugin::Razor2 - perform Razor2 check of messages

=head1 SYNOPSIS

  loadplugin     Mail::SpamAssassin::Plugin::Razor2

=over 4

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

package Mail::SpamAssassin::Plugin::Razor2;

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

  $mailsaobject->{conf}->{use_razor2} = 0;
  $mailsaobject->{conf}->{razor_timeout} = 10;

  if ($mailsaobject->{local_tests_only}) {
    dbg("razor2: local tests only, skipping razor2");
  }
  else {
    if (eval { require Razor2::Client::Agent; }) {
      dbg("razor2: razor2 is available");
      $mailsaobject->{conf}->{use_razor2} = 1;
    }
    else {
      dbg("razor2: razor2 is not available");
    }
  }

  $self->register_eval_rule ("check_razor2");
  $self->register_eval_rule ("check_razor2_range");

  return $self;
}

sub parse_config {
  my ($self, $opts) = @_;

  my $conf = $opts->{conf};
  my $key = $opts->{key};
  my $value = $opts->{value};
  my $line = $opts->{line};

  # Backward compatibility ...  use_razor2 is implicit if the plugin is loaded
  if ($key eq 'use_razor2') {
    $self->handle_parser_error($opts,
      Mail::SpamAssassin::Conf::Parser::set_numeric_value($conf, $key, $value, $line)
    );
    $self->inhibit_further_callbacks();
    return 1;
  }

=item razor_timeout n		(default: 10)

How many seconds you wait for razor to complete before you go on without
the results

=cut

  if ($key eq 'razor_timeout') {
    $self->handle_parser_error($opts,
      Mail::SpamAssassin::Conf::Parser::set_numeric_value($conf, $key, $value, $line)
    );
    $self->inhibit_further_callbacks();
    return 1;
  }

=item razor_config filename

Define the filename used to store Razor's configuration settings.
Currently this is left to Razor to decide.

=cut

  if ($key eq 'razor_config') {
    $self->handle_parser_error($opts,
      Mail::SpamAssassin::Conf::Parser::set_string_value($conf, $key, $value, $line)
    );
    $self->inhibit_further_callbacks();
    return 1;
  }

  return 0;
}

sub handle_parser_error {
  my($self, $opts, $ret_value) = @_;

  my $conf = $opts->{conf};
  my $key = $opts->{key};
  my $value = $opts->{value};
  my $line = $opts->{line};

  my $msg = '';

  if ($ret_value && $ret_value eq $Mail::SpamAssassin::Conf::INVALID_VALUE) {
    $msg = "config: SpamAssassin failed to parse line, ".
           "\"$value\" is not valid for \"$key\", ".
           "skipping: $line";
  }
  elsif ($ret_value && $ret_value eq $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE) {
    $msg = "config: SpamAssassin failed to parse line, ".
           "no value provided for \"$key\", ".
           "skipping: $line";
  }

  return unless $msg;

  if ($conf->{lint_rules}) {
    warn $msg."\n";
  } else {
    dbg($msg);
  } 
  $conf->{errors}++;
  return;
} 


sub razor2_lookup {
  my ($self, $permsgstatus, $fulltext) = @_;
  my $timeout=$self->{main}->{conf}->{razor_timeout};

  # Set the score for the ranged checks
  $self->{razor2_cf_score} = 0;
  return $self->{razor2_result} if ( defined $self->{razor2_result} );
  $self->{razor2_result} = 0;

  # this test covers all aspects of availability
  if (!$self->{main}->{conf}->{use_razor2}) { return 0; }
  
  # razor also debugs to stdout. argh. fix it to stderr...
  if ($Mail::SpamAssassin::DEBUG) {
    open (OLDOUT, ">&STDOUT");
    open (STDOUT, ">&STDERR");
  }

  $permsgstatus->enter_helper_run_mode();

    eval {
      local ($^W) = 0;    # argh, warnings in Razor

      local $SIG{ALRM} = sub { die "alarm\n" };
      alarm $timeout;

      # everything's in the module!
      my $rc = Razor2::Client::Agent->new('razor-check');

      if ($rc) {
        my %opt = (
		   debug      => ($Mail::SpamAssassin::DEBUG &&
				  $Mail::SpamAssassin::facilities->{razor}), 
		   foreground => 1,
		   config     => $self->{main}->{conf}->{razor_config}
        );
        $rc->{opt} = \%opt;
        $rc->do_conf() or die "razor2: " . $rc->errstr;

	my $tmptext = $$fulltext;
	my @msg = (\$tmptext);

        my $objects = $rc->prepare_objects( \@msg )
          or die "razor2: error in prepare_objects";
        $rc->get_server_info() or die $rc->errprefix("razor2: spamassassin");

	# let's reset the alarm since get_server_info() calls
	# nextserver() which calls discover() which very likely will
	# reset the alarm for us ... how polite.  :(  
	alarm $timeout;

        my $sigs = $rc->compute_sigs($objects)
          or die "razor2: error in compute_sigs";

        # 
        # if mail isn't whitelisted, check it out
        #   
        if ( ! $rc->local_check( $objects->[0] ) ) {
          if (!$rc->connect()) {
            # provide a better error message when servers are unavailable,
            # than "Bad file descriptor Died".
            die "razor2: could not connect to any servers\n";
          }
          $rc->check($objects) or die $rc->errprefix("razor2: spamassassin");
          $rc->disconnect() or die $rc->errprefix("razor2: spamassassin");

	  # if we got here, we're done doing remote stuff, abort the alert
	  alarm 0;

          # figure out if we have a log file we need to close...
          if (ref($rc->{logref}) && exists $rc->{logref}->{fd}) {
            # the fd can be stdout or stderr, so we need to find out if it is
	    # so we don't close them by accident.  Note: we can't just
	    # undef the fd here (like the IO::Handle manpage says we can)
	    # because it won't actually close, unfortunately. :(
            my $untie = 1;
            foreach my $log ( *STDOUT{IO}, *STDERR{IO} ) {
              if ($log == $rc->{logref}->{fd}) {
                $untie = 0;
                last;
              }
            }
            close $rc->{logref}->{fd} if ($untie);
          }

	  dbg("razor2: using results from Razor version " .
	      $Razor2::Client::Version::VERSION . "\n");

	  # so $objects->[0] is the first (only) message, and ->{spam} is a general yes/no
          $self->{razor2_result} = $objects->[0]->{spam} || 0;

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
	  if ( defined $arrayref ) {
	    foreach my $cf ( @{$arrayref} ) {
	      if ( exists $cf->{resp} ) {
	        for (my $response=0;$response<@{$cf->{resp}};$response++) {
	          my $tmp = $cf->{resp}->[$response];
	      	  my $tmpcf = $tmp->{cf} || 0; # Part confidence
	      	  my $tmpct = $tmp->{ct} || 0; # Part contested?
		  my $engine = $cf->{sent}->[$response]->{e};
	          dbg("razor2: found razor2 part: part=$part engine=$engine ct=$tmpct cf=$tmpcf");
	          $self->{razor2_cf_score} = $tmpcf if ( !$tmpct && $tmpcf > $self->{razor2_cf_score} );
	        }
	      }
	      else {
		my $text = "part=$part noresponse";
		$text .= " skipme=1" if ( $cf->{skipme} );
	        dbg("razor2: found razor2 part: $text");
	      }
	      $part++;
	    }
	  }
	  else {
	    # If we have some new $objects format that isn't close to
	    # the current razor-agents 2.x version, we won't FP but we
	    # should alert in debug.
	    dbg("razor2: it looks like the internal Razor object has changed format!");
	  }
        }
      }
      else {
        warn "razor2: undefined Razor2::Client::Agent\n";
      }
  
      alarm 0;
    };

    alarm 0;    # just in case
  
    if ($@) {
      if ( $@ =~ /alarm/ ) {
          dbg("razor2: check timed out after $timeout seconds");
        } elsif ($@ =~ /(?:could not connect|network is unreachable)/) {
          # make this a dbg(); SpamAssassin will still continue,
          # but without Razor checking.  otherwise there may be
          # DSNs and errors in syslog etc., yuck
          dbg("razor2: check could not connect to any servers");
        } else {
          warn("razor2: check skipped: $! $@");
        }
      }

  # work around serious brain damage in Razor2 (constant seed)
  srand;

  $permsgstatus->leave_helper_run_mode();

  # razor also debugs to stdout. argh. fix it to stderr...
  if ($Mail::SpamAssassin::DEBUG) {
    open (STDOUT, ">&OLDOUT");
    close OLDOUT;
  }

  dbg("razor2: results: spam? " . $self->{razor2_result} .
      "  highest cf score: " . $self->{razor2_cf_score} . "\n");

  if ($self->{razor2_result} > 0) {
      return 1;
  }
  return 0;
}

sub check_razor2 {
  my ($self, $permsgstatus) = @_;

  return unless $self->{main}->{conf}->{use_razor2};
  return $self->{razor2_result} if (defined $self->{razor2_result});

  my $full = $permsgstatus->{msg}->get_pristine();
  return $self->razor2_lookup ($permsgstatus, \$full);
}

# Check the cf value of a given message and return if it's within the
# given range
sub check_razor2_range {
  my ($self, $permsgstatus, $body, $min, $max) = @_;

  # If Razor2 isn't available, or the general test is disabled, don't
  # continue.
  return 0 unless $self->{main}->{conf}->{use_razor2};
  return 0 unless $self->{main}->{conf}->{scores}->{'RAZOR2_CHECK'};

  # If Razor2 hasn't been checked yet, go ahead and run it.
  if (!defined $self->{razor2_result}) {
    $self->check_razor2($permsgstatus);
  }

  if ($self->{razor2_cf_score} >= $min && $self->{razor2_cf_score} <= $max) {
    $permsgstatus->test_log(sprintf ("cf: %3d", $self->{razor2_cf_score}));
    return 1;
  }
  return 0;
}

sub dbg { Mail::SpamAssassin::dbg(@_); }

1;
