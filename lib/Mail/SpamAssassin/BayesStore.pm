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

Mail::SpamAssassin::BayesStore - Bayesian Storage Module

=head1 SYNOPSIS

=head1 DESCRIPTION

This is the public API for the Bayesian store methods.  Any implementation of
the storage module must implement these methods.

=cut

package Mail::SpamAssassin::BayesStore;

use strict;
use bytes;

=head1 METHODS

=head2 new

public class (Mail::SpamAssassin::BayesStore) new (Mail::SpamAssassin::Bayes $bayes)

Description:
This method creates a new instance of the Mail::SpamAssassin::BayesStore
object.  You must pass in an instance of the Mail::SpamAssassin:Bayes object,
which is stashed for use throughout the module.

=cut

sub new {
  my ($class, $bayes) = @_;

  $class = ref($class) || $class;

  my $self = {
	      'bayes'                => $bayes,
	      'supported_db_version' => 0,
	      'db_version'	     => undef,
	     };

  bless ($self, $class);

  $self;
}

=head2 DB_VERSION

public instance (Integer) DB_VERSION ()

Description:
This method returns the currently supported database version for the
implementation.

=cut

sub DB_VERSION {
  my ($self) = @_;
  return $self->{supported_db_version};
}

=head2 read_db_configs

public instance () read_db_configs ()

Description:
This method reads any needed config variables from the configuration
object and then calls the Mail::SpamAssassin::Bayes read_db_configs method.

=cut

sub read_db_configs {
  my ($self) = @_;

  # TODO: at some stage, this may be useful to read config items which
  # control database bloat, like
  #
  # - use of hapaxes
  # - use of case-sensitivity
  # - more midrange-hapax-avoidance tactics when parsing headers (future)
  # 
  # for now, we just set these settings statically.
  my $conf = $self->{bayes}->{main}->{conf};

  # Minimum desired database size?  Expiry will not shrink the
  # database below this number of entries.  100k entries is roughly
  # equivalent to a 5Mb database file.
  $self->{expiry_max_db_size} = $conf->{bayes_expiry_max_db_size};

  $self->{bayes}->read_db_configs();
}

=head2 tie_db_readonly

public instance (Boolean) tie_db_readonly ()

Description:
This method opens up the database in readonly mode.

=cut

sub tie_db_readonly {
  my ($self) = @_;
  die "tie_db_readonly: not implemented\n";
}

=head2 tie_db_writable

public instance (Boolean) tie_db_writable ()

Description:
This method opens up the database in writable mode.

Any callers of this methods should ensure that they call untie_db()
afterwards.

=cut

sub tie_db_writable {
  my ($self) = @_;
  die "tie_db_writable: not implemented\n";
}

=head2 untie_db

public instance () untie_db ()

Description:
This method unties the database.

=cut

sub untie_db {
  my $self = shift;
  die "untie_db: not implemented\n";
}

=head2 calculate_expire_delta

public instance (\%) calculate_expire_delta (Integer $newest_atime,
                                             Integer $start,
                                             Integer $max_expire_mult)

Description:
This method performs a calculation on the data to determine the optimum
atime for token expiration.

=cut

sub calculate_expire_delta {
  my ($self, $newest_atime, $start, $max_expire_mult) = @_;
  die "calculate_expire_delta: not implemented\n";
}

=head2 token_expiration

public instance (Integer, Integer,
                 Integer, Integer) token_expiration(\% $opts,
                                                    Integer $newest_atime,
                                                    Integer $newdelta)

Description:
This method performs the database specific expiration of tokens based on
the passed in C<$newest_atime> and C<$newdelta>.

=cut

sub token_expiration {
  my ($self, $opts, $newest_atime, $newdelta) = @_;
  die "token_expiration: not implemented\n";
}

=head2 expire_old_tokens

public instance (Boolean) expire_old_tokens (\% hashref)

Description:
This method expires old tokens from the database.

=cut

sub expire_old_tokens {
  my ($self, $opts) = @_;
  my $ret;

  eval {
    local $SIG{'__DIE__'};	# do not run user die() traps in here
    if ($self->tie_db_writable()) {
      $ret = $self->expire_old_tokens_trapped ($opts);
    }
  };
  my $err = $@;

  if (!$self->{bayes}->{main}->{learn_caller_will_untie}) {
    $self->untie_db();
  }

  if ($err) {		# if we died, untie the dbs.
    warn "bayes expire_old_tokens: $err\n";
    return 0;
  }
  $ret;
}

=head2 expire_old_tokens_trapped

public instance (Boolean) expire_old_tokens_trapped (\% $opts)

Description:
This methods does the actual token expiration.

XXX More docs here about the methodology and what not
=cut

sub expire_old_tokens_trapped {
  my ($self, $opts) = @_;

  # Flag that we're doing work
  $self->set_running_expire_tok();

  # We don't need to do an expire, so why were we called?  Oh well.
  if (!$self->expiry_due()) {
    $self->remove_running_expire_tok();
    return 0;
  }

  my $started = time();
  my @vars = $self->get_storage_variables();

  # How many tokens do we want to keep?
  my $goal_reduction = int($self->{expiry_max_db_size} * 0.75); # expire to 75% of max_db
  dbg("bayes: expiry check keep size, 75% of max: $goal_reduction");
  # Make sure we keep at least 100000 tokens in the DB
  if ( $goal_reduction < 100000 ) {
    $goal_reduction = 100000;
    dbg("bayes: expiry keep size too small, resetting to 100,000 tokens");
  }
  # Now turn goal_reduction into how many to expire.
  $goal_reduction = $vars[3] - $goal_reduction;
  dbg("bayes: token count: ".$vars[3].", final goal reduction size: $goal_reduction");

  if ( $goal_reduction < 1000 ) { # too few tokens to expire, abort.
    dbg("bayes: reduction goal of $goal_reduction is under 1,000 tokens.  skipping expire.");
    $self->set_last_expire(time());
    $self->remove_running_expire_tok(); # this won't be cleaned up, so do it now.
    return 1; # we want to indicate things ran as expected
  }

  # Estimate new atime delta based on the last atime delta
  my $newdelta = 0;
  if ( $vars[9] > 0 ) {
    # newdelta = olddelta * old / goal;
    # this may seem backwards, but since we're talking delta here,
    # not actual atime, we want smaller atimes to expire more tokens,
    # and visa versa.
    #
    $newdelta = int($vars[8] * $vars[9] / $goal_reduction);
  }

  # Calculate size difference between last expiration token removal
  # count and the current goal removal count.
  my $ratio = ($vars[9] == 0 || $vars[9] > $goal_reduction) ? $vars[9]/$goal_reduction : $goal_reduction/$vars[9];

  dbg("bayes: First pass?  Current: ".time().", Last: ".$vars[4].", atime: ".$vars[8].", count: ".$vars[9].", newdelta: $newdelta, ratio: $ratio");

  ## ESTIMATION PHASE
  #
  # Do this for the first expire or "odd" looking results cause a first pass to determine atime:
  #
  # - last expire was more than 30 days ago
  #   assume mail flow stays roughly the same month to month, recompute if it's > 1 month
  # - last atime delta was under 12hrs
  #   if we're expiring often max_db_size should go up, but let's recompute just to check
  # - last reduction count was < 1000 tokens
  #   ditto
  # - new estimated atime delta is under 12hrs
  #   ditto
  # - difference of last reduction to current goal reduction is > 50%
  #   if the two values are out of balance, estimating atime is going to be funky, recompute
  #
  if ( (time() - $vars[4] > 86400*30) || ($vars[8] < 43200) || ($vars[9] < 1000)
       || ($newdelta < 43200) || ($ratio > 1.5) ) {
    dbg("bayes: Can't use estimation method for expiry, something fishy, calculating optimal atime delta (first pass)");

    my $start = 43200; # exponential search starting at ...?  1/2 day, 1, 2, 4, 8, 16, ...
    my $max_expire_mult = 512; # $max_expire_mult * $start = max expire time (256 days), power of 2.

    my %delta = $self->calculate_expire_delta($vars[10], $start, $max_expire_mult);

    return 0 unless (%delta);

    # This will skip the for loop if debugging isn't enabled ...
    if ( $Mail::SpamAssassin::DEBUG->{'enabled'} ) {
      dbg("bayes: atime\ttoken reduction");
      dbg("bayes: ========\t===============");
      for( my $i = 1; $i<=$max_expire_mult; $i<<=1 ) {
	  dbg("bayes: ".$start*$i."\t".(exists $delta{$i} ? $delta{$i} : 0));
      }
    }
  
    # Now figure out which max_expire_mult value gives the closest results to goal_reduction, without
    # going over ...  Go from the largest delta backwards so the reduction size increases
    # (tokens that expire at 4 also expire at 3, 2, and 1, so 1 will always be the largest expiry...)
    #
    for( ; $max_expire_mult > 0; $max_expire_mult>>=1 ) {
      next unless exists $delta{$max_expire_mult};
      if ($delta{$max_expire_mult} > $goal_reduction) {
        $max_expire_mult<<=1; # the max expire is actually the next power of 2 out
        last;
      }
    }

    # if max_expire_mult gets to 0, either we can't expire anything, or 1 is <= $goal_reduction
    $max_expire_mult ||= 1;

    # $max_expire_mult is now equal to the value we should use ...
    # Check to see if the atime value we found is really good.
    # It's not good if:
    # - $max_expire_mult would not expire any tokens.  This means that the majority of
    #   tokens are old or new, and more activity is required before an expiry can occur.
    # - reduction count < 1000, not enough tokens to be worth doing an expire.
    #
    if ( !exists $delta{$max_expire_mult} || $delta{$max_expire_mult} < 1000 ) {
      dbg("bayes: couldn't find a good delta atime, need more token difference, skipping expire.");
      $self->set_last_expire(time());
      $self->remove_running_expire_tok(); # this won't be cleaned up, so do it now.
      return 1; # we want to indicate things ran as expected
    }

    $newdelta = $start * $max_expire_mult;
    dbg("bayes: First pass decided on $newdelta for atime delta");
  }
  else { # use the estimation method
    dbg("bayes: Can do estimation method for expiry, skipping first pass.");
  }

  my ($kept, $deleted, $num_hapaxes, $num_lowfreq) = $self->token_expiration($opts, $newdelta, @vars);

  my $done = time();

  my $msg = "expired old Bayes database entries in ".($done - $started)." seconds";
  my $msg2 = "$kept entries kept, $deleted deleted";

  if ($opts->{verbose}) {

    my $hapax_pc = ($num_hapaxes * 100) / $kept;
    my $lowfreq_pc = ($num_lowfreq * 100) / $kept;
    print "$msg\n$msg2\n";
    printf "token frequency: 1-occurence tokens: %3.2f%%\n", $hapax_pc;
    printf "token frequency: less than 8 occurrences: %3.2f%%\n", $lowfreq_pc;
  } else {
    dbg ("$msg: $msg2");
  }

  return 1;
}

=head2 sync_due

public instance (Boolean) sync_due ()

Description:
This methods determines if a sync is due.

=cut

sub sync_due {
  my ($self) = @_;
  die "sync_due: not implemented\n";
}

=head2 expiry_due

public instance (Boolean) expiry_due ()

Description:
This methods determines if an expire is due.

=cut

sub expiry_due {
  my ($self) = @_;

  $self->read_db_configs();	# make sure this has happened here

  # If force expire was called, do the expire no matter what.
  return 1 if ($self->{bayes}->{main}->{learn_force_expire});

  # is the database too small for expiry?  (Do *not* use "scalar keys",
  # as this will iterate through the entire db counting them!)
  my @vars = $self->get_storage_variables();
  my $ntoks = $vars[3];

  my $last_expire = time() - $vars[4];
  if (!$self->{bayes}->{main}->{ignore_safety_expire_timeout}) {
    # if we're not ignoring the safety timeout, don't run an expire more
    # than once every 12 hours.
    return 0 if ($last_expire < 43200);
  }
  else {
    # if we are ignoring the safety timeout (e.g.: mass-check), still
    # limit the expiry to only one every 5 minutes.
    return 0 if ($last_expire < 300);
  }

  dbg("Bayes DB expiry: Tokens in DB: $ntoks, Expiry max size: ".$self->{expiry_max_db_size}.", Oldest atime: ".$vars[5].", Newest atime: ".$vars[10].", Last expire: ".$vars[4].", Current time: ".time(),'bayes','-1');

  my $conf = $self->{bayes}->{main}->{conf};
  if ($ntoks <= 100000 ||			# keep at least 100k tokens
      $conf->{bayes_auto_expire} == 0 ||	# config says don't expire
      $self->{expiry_max_db_size} > $ntoks ||	# not enough tokens to cause an expire
      $vars[10]-$vars[5] < 43200 ||		# delta between oldest and newest < 12h
      $self->{db_version} < $self->DB_VERSION # ignore old db formats
      ) {
    return 0;
  }

  return 1;
}

=head2 seen_get

public instance (Char) seen_get (String $msgid)

Description:
This method retrieves the stored value, if any, for C<$msgid>.  The return
value is the stored string ('s' for spam and 'h' for ham) or undef if
C<$msgid> is not found.

=cut

sub seen_get {
  my ($self, $msgid) = @_;
  die "seen_get: not implemented\n";
}

=head2 seen_put

public instance (Boolean) seen_put (String $msgid, Char $flag)

Description:
This method records C<$msgid> as the type given by C<$flag>.  C<$flag> is
one of two values 's' for spam and 'h' for ham.

=cut

sub seen_put {
  my ($self, $msgid, $flag) = @_;
  die "seen_put: not implemented\n";
}

=head2 seen_delete

public instance (Boolean) seen_delete (String $msgid)

Description:
This method removes C<$msgid> from storage.

=cut

sub seen_delete {
  my ($self, $msgid) = @_;
  die "seen_delete: not implemented\n";
}

=head2 get_storage_variables

public instance (@) get_storage_variables ()

Description:
This method retrieves the various administrative variables used by
the Bayes storage implementation.

The values returned in the array are in the following order:

0: scan count base

1: number of spam

2: number of ham

3: number of tokens in db

4: last expire atime

5: oldest token in db atime

6: db version value

7: last journal sync

8: last atime delta

9: last expire reduction count

10: newest token in db atime

=cut

sub get_storage_variables {
  my ($self) = @_;
  die "get_storage_variables: not implemented\n";
}

=head2 dump_db_toks

public instance () dump_db_toks (String $template, String $regex, @ @vars)

Description:
This method loops over all tokens, computing the probability for the token
and then printing it out according to the passed in template.

=cut

sub dump_db_toks {
  my ($self, $template, $regex, @vars) = @_;
  die "dump_db_toks: not implemented\n";
}

=head2 set_last_expire

public instance (Boolean) _set_last_expire (Integer $time)

Description:
This method sets the last expire time.

=cut

sub set_last_expire {
  my ($self, $time) = @_;
  die "set_last_expire: not implemented\n";
}

=head2 get_running_expire_tok

public instance (Time) get_running_expire_tok ()

Description:
This method determines if an expire is currently running and returns the time
the expire started.

=cut

sub get_running_expire_tok {
  my ($self) = @_;
  die "get_running_expire_tok: not implemented\n";
}

=head2 set_running_expire_tok

public instance (Time) set_running_expire_tok ()

Description:
This method sets the running expire time to the current time.

=cut

sub set_running_expire_tok {
  my ($self) = @_;
  die "set_running_expire_tok: not implemented\n";
}

=head2 remove_running_expire_tok

public instance (Boolean) remove_running_expire_tok ()

Description:
This method removes a currently set running expire time.

=cut

sub remove_running_expire_tok {
  my ($self) = @_;
  die "remove_running_expire_tok: not implemented\n";
}

=head2 tok_get

public instance (Integer, Integer, Time) tok_get (String $token)

Description:
This method retrieves the specified token (C<$token>) from storage and returns
it's spam count, ham acount and last access time.

=cut

sub tok_get {
  my ($self, $token) = @_;
  die "tok_get: not implemented\n";
}

=head2 tok_count_change

public instance (Boolean) tok_count_change (Integer $spam_count,
                                            Integer $ham_count,
                                            String $token,
                                            Time $atime)

Description:
This method takes a C<$spam_count> and C<$ham_count> and adds it to
C<$token> along with updating C<$token>s atime with C<$atime>.

=cut

sub tok_count_change {
  my ($self, $spam_count, $ham_count, $token, $atime) = @_;
  die "tok_count_change: not implemented\n";
}

=head2 nspam_nham_get

public instance (Integer, Integer) nspam_nham_get ()

Description:
This method retrieves the total number of spam and the total number of spam
currently under storage.

=cut

sub nspam_nham_get {
  my ($self) = @_;
  die "nspam_nham_get: not implemented\n";
}

=head2 nspam_nham_change

public instance (Boolean) nspam_nham_change (Integer $num_spam,
                                             Integer $num_ham)

Description:
This method updates the number of spam and the number of ham in the database.

=cut

sub nspam_nham_change {
  my ($self, $num_spam, $num_ham) = @_;
  die "nspam_nham_change: not implemented\n";
}

=head2 tok_touch

public instance (Boolean) tok_touch (String $token,
                                     Time $atime)

Description:
This method updates the given tokens (C<$token>) access time.

=cut

sub tok_touch {
  my ($self, $token, $atime) = @_;
  die "tok_touch: not implemanted\n";
}

=head2 cleanup

public instance (Boolean) cleanup ()

Description:
This method performs any cleanup necessary before moving onto the next
operation.

=cut

sub cleanup {
  my ($self) = @_;
  die "touches_cleanup: not implemented\n";
}

=head2 is_magic_token

public instance (Boolean) is_magic_token (string $token)

Description:
This method determines if a given token is "magic" or special to the
implementation.

=cut

sub is_magic_token {
  my ($self, $token) = @_;
  die "is_magic_token: not implemented\n";
}

=head2 sync

public instance (Boolean) sync (\% $opts)

Description:
This method performs a sync of the database.

=cut

sub sync {
  my ($self, $opts) = @_;
  die "sync: not implemented\n";
}

=head2 scan_count_get

public instance (Integer) scan_count_get ()

Description:
This method gets the current scan count, if used by the implementation.

=cut

sub scan_count_get {
  my ($self) = @_;
  die "scan_count_get: not implemented\n";
}

=head2 perform_upgrade

public instance (Boolean) perform_upgrade (\% $opts)

Description:
This method is a utility method that performs any necessary upgrades
between versions.  It should know how to handle previous versions and
what needs to happen to upgrade them.

A true return value indicates success.

=cut

sub perform_upgrade {
  my ($self, $opts) = @_;
  die "perform_upgrade: not implemented\n";
}

sub dbg { Mail::SpamAssassin::dbg (@_); }
sub sa_die { Mail::SpamAssassin::sa_die (@_); }

1;
