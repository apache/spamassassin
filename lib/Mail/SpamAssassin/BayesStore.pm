package Mail::SpamAssassin::BayesStore;

use strict;
use bytes;
use Fcntl;

BEGIN { @AnyDBM_File::ISA = qw(DB_File GDBM_File NDBM_File SDBM_File); }
use AnyDBM_File;

use Mail::SpamAssassin;
use Mail::SpamAssassin::Util;
use Sys::Hostname;
use File::Basename;
use File::Spec;
use File::Path;

use vars qw{
  @ISA
  @DBNAMES @DB_EXTENSIONS
  $NSPAM_MAGIC_TOKEN $NHAM_MAGIC_TOKEN $LAST_EXPIRE_MAGIC_TOKEN
  $NTOKENS_MAGIC_TOKEN $OLDEST_TOKEN_AGE_MAGIC_TOKEN
  $SCANCOUNT_BASE_MAGIC_TOKEN 
};

@ISA = qw();

# db layout (quoting Matt):
#
# > need five db files though to make it real fast:
# [probs] 1. ngood and nbad (two entries, so could be a flat file rather 
# than a db file).	(now 2 entries in db_toks)
# [toks]  2. good token -> number seen
# [toks]  3. bad token -> number seen (both are packed into 1 entry in 1 db)
# [probs]  4. Consolidated good token -> probability
# [probs]  5. Consolidated bad token -> probability
# > As you add new mails, you update the entry in 2 or 3, then regenerate
# > the entry for that token in 4 or 5.
# > Then as you test a new mail, you just need to pull the probability
# > direct from 4 and 5, and generate the overall probability. A simple and
# > very fast operation. 
#
# jm: we use probs as overall probability. <0.5 = ham, >0.5 = spam
#
# update: probs is no longer maintained as a db, to keep on-disk and in-core
# usage down.
#
# also, added a new one to support forgetting, auto-learning, and
# auto-forgetting for refiled mails:
# [seen]  6. a list of Message-IDs of messages already learnt from. values
# are 's' for learnt-as-spam, 'h' for learnt-as-ham.
#
# and another, called [scancount] to model the scan-count for expiry.
# This is not a database.  Instead it increases by one byte for each
# message scanned (note: scanned, not learned).

@DBNAMES = qw(toks seen);

# Possible file extensions used by the kinds of database files AnyDBM
# might create.  We need these so we can create a new file and rename
# it into place.
@DB_EXTENSIONS = ('', '.db', '.dir', '.pag', '.dbm', '.cdb');

$NSPAM_MAGIC_TOKEN = '**NSPAM';
$NHAM_MAGIC_TOKEN = '**NHAM';
$OLDEST_TOKEN_AGE_MAGIC_TOKEN = '**OLDESTAGE';
$LAST_EXPIRE_MAGIC_TOKEN = '**LASTEXPIRE';
$NTOKENS_MAGIC_TOKEN = '**NTOKENS';
$SCANCOUNT_BASE_MAGIC_TOKEN = '**SCANBASE';

use constant MAX_SIZE_FOR_SCAN_COUNT_FILE => 5000;

###########################################################################

sub new {
  my $class = shift;
  $class = ref($class) || $class;
  my ($bayes) = @_;
  my $self = {
    'bayes'             => $bayes,
    'already_tied'	=> 0,
    'is_locked'		=> 0,
    'string_to_journal' => '',
  };
  bless ($self, $class);

  $self;
}

###########################################################################

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

  # Expire tokens that have not been accessed in this many messages?
  $self->{expiry_count} = $conf->{bayes_expiry_scan_count};

  # Minimum desired database size?  Expiry will not shrink the
  # database below this number of entries.  100k entries is roughly
  # equivalent to a 5Mb database file.
  $self->{expiry_min_db_size} = $conf->{bayes_expiry_min_db_size};

  $self->{bayes}->read_db_configs();
}

###########################################################################

sub tie_db_readonly {
  my ($self) = @_;
  my $main = $self->{bayes}->{main};

  # return if we've already tied to the db's, using the same mode
  # (locked/unlocked) as before.
  return 1 if ($self->{already_tied} && $self->{is_locked} == 0);
  $self->{already_tied} = 1;

  $self->read_db_configs();

  if (!defined($main->{conf}->{bayes_path})) {
    dbg ("bayes_path not defined");
    return 0;
  }

  my $path = $main->sed_path ($main->{conf}->{bayes_path});

  my $found=0;
  for my $ext (@DB_EXTENSIONS) { if (-f $path.'_toks'.$ext) { $found=1; last; } }

  if (!$found) {
    dbg ("bayes: no dbs present, cannot scan: ${path}_toks");
    return 0;
  }

  foreach my $dbname (@DBNAMES) {
    my $name = $path.'_'.$dbname;
    my $db_var = 'db_'.$dbname;
    dbg("bayes: tie-ing to DB file R/O $name");
    # untie %{$self->{$db_var}} if (tied %{$self->{$db_var}});
    tie %{$self->{$db_var}},"AnyDBM_File",$name, O_RDONLY,
		 (oct ($main->{conf}->{bayes_file_mode}) & 0666)
       or goto failed_to_tie;
  }
  $self->{scan_count_little_file} = $path.'_msgcount';
  return 1;

failed_to_tie:
  warn "Cannot open bayes databases ${path}_* R/O: tie failed: $!\n";
  return 0;
}

# tie() to the databases, read-write and locked.  Any callers of
# this should ensure they call untie_db() afterwards!
#
sub tie_db_writable {
  my ($self) = @_;
  my $main = $self->{bayes}->{main};

  # return if we've already tied to the db's, using the same mode
  # (locked/unlocked) as before.
  return 1 if ($self->{already_tied} && $self->{is_locked} == 1);
  $self->{already_tied} = 1;

  $self->read_db_configs();

  if (!defined($main->{conf}->{bayes_path})) {
    dbg ("bayes_path not defined");
    return 0;
  }

  my $path = $main->sed_path ($main->{conf}->{bayes_path});

  my $parentdir = dirname ($path);
  if (!-d $parentdir) {
    # run in an eval(); if mkpath has no perms, it calls die()
    eval {
      mkpath ($parentdir, 0, (oct ($main->{conf}->{bayes_file_mode}) & 0777));
    };
  }

  if ($main->{locker}->safe_lock ($path)) {
    $self->{locked_file} = $path;
    $self->{is_locked} = 1;
  } else {
    warn "Cannot open bayes databases ${path}_* R/W: lock failed: $!\n";
    return 0;
  }

  my $umask = umask 0;
  foreach my $dbname (@DBNAMES) {
    my $name = $path.'_'.$dbname;
    my $db_var = 'db_'.$dbname;
    dbg("bayes: tie-ing to DB file R/W $name");
    # not convinced this is needed, or is efficient!
    # untie %{$self->{$db_var}} if (tied %{$self->{$db_var}});
    tie %{$self->{$db_var}},"AnyDBM_File",$name, O_RDWR|O_CREAT,
		 (oct ($main->{conf}->{bayes_file_mode}) & 0666)
       or goto failed_to_tie;
  }
  umask $umask;
  $self->{scan_count_little_file} = $path.'_msgcount';

  # ensure we count 1 mailbox learnt as an event worth marking,
  # expiry-wise
  $self->scan_count_increment();

  return 1;

failed_to_tie:
  my $err = $!;
  umask $umask;
  if ($self->{is_locked}) {
    $self->{bayes}->{main}->{locker}->safe_unlock ($self->{locked_file});
    $self->{is_locked} = 0;
  }
  warn "Cannot open bayes databases ${path}_* R/W: tie failed: $err\n";
  return 0;
}

###########################################################################

sub untie_db {
  my $self = shift;
  dbg("bayes: untie-ing");

  foreach my $dbname (@DBNAMES) {
    my $db_var = 'db_'.$dbname;

    if (exists $self->{$db_var}) {
      dbg ("bayes: untie-ing $db_var");
      untie %{$self->{$db_var}};
      delete $self->{$db_var};
    }
  }

  if ($self->{is_locked}) {
    dbg ("bayes: files locked, now unlocking lock");
    $self->{bayes}->{main}->{locker}->safe_unlock ($self->{locked_file});
    $self->{is_locked} = 0;
  }

  $self->{already_tied} = 0;
}

###########################################################################

# Do an expiry run.
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

  $self->untie_db();
  if ($err) {		# if we died, untie the dbs.
    warn "bayes expire_old_tokens: $err\n";
    return 0;
  }
  $ret;
}

sub expire_old_tokens_trapped {
  my ($self, $opts) = @_;

  if (!$self->expiry_due() && !$self->{bayes}->{main}->{learn_force_expire})
				{ return 0; }

  my $too_old = $self->scan_count_get();
  $too_old = ($too_old < $self->{expiry_count} ? 
				0 : $too_old - $self->{expiry_count});

  my $deleted = 0;
  my $kept = 0;
  my $num_lowfreq = 0;
  my $num_hapaxes = 0;
  my $started = time();
  my $last = $self->{db_toks}->{$LAST_EXPIRE_MAGIC_TOKEN};
  if (!$last || $last =~ /\D/) { $last = 0; }
  my $current = $self->scan_count_get();

  # since DB_File will not shrink a database (!!), we need to *create*
  # a new one instead.
  my $main = $self->{bayes}->{main};
  my $path = $main->sed_path ($main->{conf}->{bayes_path});
  my $name = $path.'_toks.new';

  # use O_EXCL to avoid races (bonus paranoia, since we should be locked
  # anyway)
  my %new_toks;
  my $umask = umask 0;
  tie %new_toks, "AnyDBM_File", $name, O_RDWR|O_CREAT|O_EXCL,
	       (oct ($main->{conf}->{bayes_file_mode}) & 0666);
  umask $umask;
  my @deleted_toks;
  my $oldest;

  my $showdots = $opts->{showdots};
  if ($showdots) { print STDERR "\n"; }

  foreach my $tok (keys %{$self->{db_toks}}) {
    next if ($tok eq $NSPAM_MAGIC_TOKEN
	  || $tok eq $NHAM_MAGIC_TOKEN
	  || $tok eq $LAST_EXPIRE_MAGIC_TOKEN
	  || $tok eq $NTOKENS_MAGIC_TOKEN
	  || $tok eq $OLDEST_TOKEN_AGE_MAGIC_TOKEN
	  || $tok eq $SCANCOUNT_BASE_MAGIC_TOKEN);

    my ($ts, $th, $atime) = $self->tok_get ($tok);

    # If the current token atime is > than the current scan count,
    # there was likely a DB expiry error.  Let's reset the atime to the
    # last expire time.
    if ($atime > $current) {
      $atime = $last;
    }

    if ($atime < $too_old) {
      push (@deleted_toks, [ $tok, $ts, $th, $atime ]);
      $deleted++;

    } else {
      $new_toks{$tok} = tok_pack ($ts, $th, $atime); $kept++;
      if (!defined($oldest) || $atime < $oldest) { $oldest = $atime; }
      if ($ts + $th == 1) {
	$num_hapaxes++;
      } elsif ($ts < 8 && $th < 8) {
	$num_lowfreq++;
      }
    }

    if ($showdots && (($kept + $deleted) % 1000) == 0) {
      print STDERR ".";
    }
  }

  # ok, we've expired: now, is the db too small?  If so, add back in
  # some of the toks we deleted.
  my $reprieved = 0;

  while ($kept+$reprieved < $self->{expiry_min_db_size} && $deleted > 0) {
    my $deld = shift @deleted_toks;
    my ($tok, $ts, $th, $atime) = @{$deld};
    next unless (defined $tok && defined $ts && defined $th);
    $new_toks{$tok} = tok_pack ($ts, $th, $atime);
    if (defined($atime) && (!defined($oldest) || $atime < $oldest)) {
      $oldest = $atime;
    }
    $reprieved++;
  }
  @deleted_toks = ();		# free 'em up
  $deleted -= $reprieved;

  # and add the magic tokens
  $new_toks{$SCANCOUNT_BASE_MAGIC_TOKEN} = $self->{db_toks}->{$SCANCOUNT_BASE_MAGIC_TOKEN};
  $new_toks{$LAST_EXPIRE_MAGIC_TOKEN} = $self->scan_count_get();
  $new_toks{$OLDEST_TOKEN_AGE_MAGIC_TOKEN} = $oldest;
  $new_toks{$NSPAM_MAGIC_TOKEN} = $self->{db_toks}->{$NSPAM_MAGIC_TOKEN};
  $new_toks{$NHAM_MAGIC_TOKEN} = $self->{db_toks}->{$NHAM_MAGIC_TOKEN};
  $new_toks{$NTOKENS_MAGIC_TOKEN} = $kept + $reprieved;

  # now untie so we can do renames
  untie %{$self->{db_toks}};
  untie %new_toks;

  # now rename in the new one.  Try several extensions
  for my $ext (@DB_EXTENSIONS) {
    my $newf = $path.'_toks.new'.$ext;
    my $oldf = $path.'_toks'.$ext;
    next unless (-f $newf);
    if (!rename ($newf, $oldf)) {
      warn "rename $newf to $oldf failed: $!\n";
    }
  }

  # ok, once that's done we can re-tie.  Call untie_db() first so
  # we unlock correctly etc. first
  $self->untie_db();
  $self->tie_db_writable();

  my $done = time();

  my $msg = "expired old Bayes database entries in ".($done - $started)." seconds";
  my $msg2 = "$kept entries kept, $reprieved reprieved, $deleted deleted";

  if ($opts->{verbose}) {
    my $hapax_pc = ($num_hapaxes * 100) / ($kept+$reprieved || 0.001);
    my $lowfreq_pc = ($num_lowfreq * 100) / ($kept+$reprieved || 0.001);
    print "$msg\n$msg2\n";
    printf "token frequency: 1-occurence tokens: %3.2f%%\n", $hapax_pc;
    printf "token frequency: less than 8 occurrences: %3.2f%%\n", $lowfreq_pc;
  } else {
    dbg ("$msg: $msg2");
  }

  1;
}

###########################################################################

# Is an expiry run due to occur?
sub expiry_due {
  my ($self) = @_;

  $self->read_db_configs();	# make sure this has happened here

  # is the database too small for expiry?  (Do *not* use "scalar keys",
  # as this will iterate through the entire db counting them!)
  my $ntoks = $self->{db_toks}->{$NTOKENS_MAGIC_TOKEN};

  # grr, wierd warning about non-numeric data. work around it
  if (!$ntoks || $ntoks =~ /\D/) 
		{ $ntoks = $self->{expiry_min_db_size} + 1; }

  dbg("Bayes DB expiry: Tokens in DB: $ntoks, Expiry min size: ".$self->{expiry_min_db_size},'bayes','-1');

  if ($ntoks <= $self->{expiry_min_db_size}) {
    return 0;
  }

  my $last = $self->{db_toks}->{$LAST_EXPIRE_MAGIC_TOKEN};
  if (!$last || $last =~ /\D/) { $last = 0; }
  my $oldest = $self->{db_toks}->{$OLDEST_TOKEN_AGE_MAGIC_TOKEN};
  if (!$oldest || $oldest =~ /\D/) { $oldest = 0; }

  my $limit = $self->{expiry_count};
  my $now = $self->scan_count_get();

  dbg("Bayes DB expiry: Now: $now, Last: $last, Limit: $limit, Oldest: $oldest",'bayes','-1');

  if (($now - $last > $limit/2 && $now - $oldest > $limit) || ($now < $last)) {
    return 1;
  }

  0;
}

###########################################################################
# db_seen reading APIs

sub seen_get {
  my ($self, $msgid) = @_;
  $self->{db_seen}->{$msgid};
}

sub seen_put {
  my ($self, $msgid, $seen) = @_;
  $self->{db_seen}->{$msgid} = $seen;
}

sub seen_delete {
  my ($self, $msgid) = @_;
  delete $self->{db_seen}->{$msgid};
}

###########################################################################
# db reading APIs

sub tok_get {
  my ($self, $tok) = @_;
  my ($ts, $th, $atime) = tok_unpack ($self->{db_toks}->{$tok});
  ($ts, $th, $atime);
}
 
sub nspam_nham_get {
  my ($self) = @_;
  my $ns = $self->{db_toks}->{$NSPAM_MAGIC_TOKEN};
  my $nn = $self->{db_toks}->{$NHAM_MAGIC_TOKEN};
  ($ns || 0, $nn || 0);
}

###########################################################################

# db abstraction: allow deferred writes, since we will be frequently
# writing while checking.

sub tok_count_change {
  my ($self, $ds, $dh, $tok) = @_;

  # To defer writes while learning:
  #$self->defer_update ("c $ds $dh ".$self->expiry_now()." ".$tok);

  # To write immediately:
  $self->tok_sync_counters ($ds, $dh, $self->expiry_now(), $tok);
}
 
sub nspam_nham_change {
  my ($self, $ds, $dh) = @_;

  # To defer writes while learning:
  #$self->defer_update ("n $ds $dh");

  # To write immediately:
  $self->tok_sync_nspam_nham ($ds, $dh);
}

sub tok_touch {
  my ($self, $tok) = @_;
  $self->defer_update ("t ".$self->expiry_now()." ".$tok);
}

sub defer_update {
  my ($self, $str) = @_;
  $self->{string_to_journal} .= $str."\n";
}

sub add_touches_to_journal {
  my ($self) = @_;
  my $path = $self->get_journal_filename();

  # use append mode, write atomically, then close, so simultaneous updates are
  # not lost
  my $conf = $self->{bayes}->{main}->{conf};
  my $umask = umask(0777 - (oct ($conf->{bayes_file_mode}) & 0666));
  if (!open (OUT, ">>".$path)) {
    warn "cannot write to $path, Bayes db update ignored\n";
    umask $umask; # reset umask
    return;
  }
  print OUT $self->{string_to_journal};
  if (!close OUT) {
    warn "cannot write to $path, Bayes db update ignored\n";
  }
  umask $umask; # reset umask

  $self->{string_to_journal} = '';
}

sub expiry_now {
  my ($self) = @_;
  $self->scan_count_get();
}

###########################################################################
# And this method reads the journal and applies the changes in one
# (locked) transaction.

sub sync_journal {
  my ($self, $opts) = @_;

  my $path = $self->get_journal_filename();

  if (!-f $path) { return 0; }

  # retire the journal, so we can update the db files from it in peace.
  # TODO: use locking here
  my $retirepath = $path.".old";
  if (!rename ($path, $retirepath)) {
    warn "bayes: failed rename $path to $retirepath\n";
    return 0;
  }

  my $started = time();
  my $count = 0;

  my $showdots = $opts->{showdots};

  # now read the retired journal
  if (!open (JOURNAL, "<".$retirepath)) {
    warn "bayes: cannot open read $retirepath\n";
    rename($retirepath,$path); # try to put it back if we can...
    return 0;
  }

  my $ok_to_remove = 0;
  eval {
    local $SIG{'__DIE__'};	# do not run user die() traps in here
    my %tokens = ();

    if ($self->tie_db_writable()) {
      while (<JOURNAL>) {
        if (/^t (\d+) (.*)$/) {
	  $tokens{$2} = $1+0;
#        } elsif (/^c (-?\d+) (-?\d+) (\d+) (.*)$/) {
#          $self->tok_sync_counters ($1+0, $2+0, $3+0, $4);
#        } elsif (/^n (-?\d+) (-?\d+)$/) {
#          $self->tok_sync_nspam_nham ($1+0, $2+0);
        } else {
          warn "Bayes journal: gibberish: $_";
        }

      }

      # Now that we've determined the tokens and their final values,
      # update the DB.  Should be much smaller than the full journal
      # entries.
      while( my($k,$v) = each %tokens ) {
        $self->tok_touch_token ($v, $k);

        if ($showdots && ($count++ % 1000) == 0) {
          print STDERR ".";
        }
      }
      $ok_to_remove = 1;
    }
  };
  my $err = $@;

  if ($showdots) { print STDERR "\n"; }

  # ok, untie from write-mode, delete the retired journal
  $self->untie_db();
  close JOURNAL;
  if ($ok_to_remove) {
    unlink ($retirepath);
  }
  else {
    warn "bayes: Detected problem syncing journal, trying to rename $retirepath to $path\n";
    rename($retirepath,$path) or warn "bayes: rename failed"; # try to put it back if we can...

    # handle any errors that may have occurred
    if ($err) {
      warn "bayes: $err\n";
      return 0;
    }
  }

  my $done = time();
  my $msg = ("synced Bayes databases from journal in ".($done - $started).
	" seconds: $count unique entries");

  if ($opts->{verbose}) {
    print $msg,"\n";
  } else {
    dbg ($msg);
  }

  # else, that's the lot, we're synced.  return
  1;
}

sub tok_touch_token {
  my ($self, $atime, $tok) = @_;
  my ($ts, $th, $oldatime) = $self->tok_get ($tok);

  # If the new atime is < the old atime, ignore the update
  # We figure that we'll never want to lower a token atime, so abort if
  # we try.  (journal out of sync, etc.)
  return if ( $oldatime >= $atime );

  $self->tok_put ($tok, $ts, $th, $atime);
}

sub tok_sync_counters {
  my ($self, $ds, $dh, $atime, $tok) = @_;
  my ($ts, $th, $oldatime) = $self->tok_get ($tok);
  $ts += $ds; if ($ts < 0) { $ts = 0; }
  $th += $dh; if ($th < 0) { $th = 0; }
  $self->tok_put ($tok, $ts, $th, $atime);
}

sub tok_put {
  my ($self, $tok, $ts, $th, $atime) = @_;
  $ts ||= 0;
  $th ||= 0;

  my $exists_already = exists $self->{db_toks}->{$tok};

  if ($ts == 0 && $th == 0) {
    if ($exists_already) { # If the token exists, lower the token count
      $self->{db_toks}->{$NTOKENS_MAGIC_TOKEN}--;
    }

    delete $self->{db_toks}->{$tok};
  } else {
    if (!$exists_already) { # If the token doesn't exist, raise the token count
      $self->{db_toks}->{$NTOKENS_MAGIC_TOKEN}++;
    }

    $self->{db_toks}->{$tok} = tok_pack ($ts, $th, $atime);
  }
}

sub tok_sync_nspam_nham {
  my ($self, $ds, $dh) = @_;
  my $ns = $self->{db_toks}->{$NSPAM_MAGIC_TOKEN};
  my $nh = $self->{db_toks}->{$NHAM_MAGIC_TOKEN};
  $ns ||= 0;
  $nh ||= 0;
  if ($ds) { $ns += $ds; } if ($ns < 0) { $ns = 0; }
  if ($dh) { $nh += $dh; } if ($nh < 0) { $nh = 0; }
  $self->{db_toks}->{$NSPAM_MAGIC_TOKEN} = $ns;
  $self->{db_toks}->{$NHAM_MAGIC_TOKEN} = $nh;
}

###########################################################################

sub get_journal_filename {
  my ($self) = @_;

  if (defined $self->{journal_live_path}) {
    return $self->{journal_live_path};
  }

  my $main = $self->{bayes}->{main};
  my $fname = $main->sed_path ($main->{conf}->{bayes_path}."_journal");

  $self->{journal_live_path} = $fname;
  return $self->{journal_live_path};
}

###########################################################################

sub scan_count_get {
  my ($self) = @_;

  my $count = $self->{db_toks}->{$SCANCOUNT_BASE_MAGIC_TOKEN};
  # avoid a wierd warning: non-numeric data in there
  if (!$count || $count =~ /\D/) { $count = 0; }
  my $path = $self->{scan_count_little_file};
  $count += (defined $path && -e $path ? -s _ : 0);
  $count;
}

sub scan_count_increment {
  my ($self) = @_;

  my $path = $self->{scan_count_little_file};
  return unless defined($path);

  # Use filesystem-level append operations.  These are very fast, and
  # on a local disk on UNIX at least, guaranteed not to overwrite another
  # process' changes.   Note that, if they do clobber someone else's
  # ".", this is not a big deal; it'll just take a tiny bit longer to
  # perform an expiry.  Not a serious failure mode, so don't worry about
  # it ;)

  my $conf = $self->{bayes}->{main}->{conf};
  my $umask = umask(0777 - (oct ($conf->{bayes_file_mode}) & 0666));
  if (!open (OUT, ">>".$path)) {
    warn "cannot write to $path, Bayes db update ignored\n";
    umask $umask; # reset umask
    return;
  }
  print OUT "."; close OUT or warn "cannot append to $path\n";
  umask $umask; # reset umask

  # note the tiny race cond between close above, and this -s.  Again, if we
  # miss a . or two, it won't make much of a difference.
  if (-s $path > MAX_SIZE_FOR_SCAN_COUNT_FILE) {
    $self->scan_count_increment_big_counter() && unlink ($path);
  }

  1;
}

# once every MAX_SIZE_FOR_SCAN_COUNT_FILE scans, we need to perform a write on
# the locked db to update the "big counter".  This method does that.
#
sub scan_count_increment_big_counter {
  my ($self) = @_;

  # ensure we return back to the lock-status we were at afterwards...
  my $need_to_retie_ro = 0;
  my $need_to_untie = 0;
  if (!$self->{already_tied}) {
    $need_to_untie = 1;
  } elsif (!$self->{is_locked}) {
    $need_to_retie_ro = 1;
  }

  eval {
    local $SIG{'__DIE__'};      # do not run user die() traps in here

    if ($self->tie_db_writable()) {
      my $count = $self->{db_toks}->{$SCANCOUNT_BASE_MAGIC_TOKEN};
      if (!$count || $count =~ /\D/) { $count = 0; }
      $count += MAX_SIZE_FOR_SCAN_COUNT_FILE;
      $self->{db_toks}->{$SCANCOUNT_BASE_MAGIC_TOKEN} = $count;
    }
  };

  my $failure;
  if ($@) {             # if we died, untie the dbs.
    my $failure = $@;
  }

  if ($need_to_untie || $need_to_retie_ro) {
    $self->untie_db();
  }
  if ($need_to_retie_ro) {
    $self->tie_db_readonly();
  }

  if ($failure) {
    warn "bayes scan_count_increment_big_counter: $failure\n";
    return 0;
  }

  1;
}

###########################################################################

# token marshalling format for db_toks.

# Since we may have many entries with few hits, especially thousands of hapaxes
# (1-occurrence entries), use a flexible entry format, instead of simply "2
# packed ints", to keep the memory and disk space usage down.  In my
# 18k-message test corpus, only 8.9% have >= 8 hits in either counter, so we
# can use a 1-byte representation for the other 91% of low-hitting entries
# and save masses of space.

# This looks like: XXSSSHHH (XX = format bits, SSS = 3 spam-count bits, HHH = 3
# ham-count bits).  If XX in the first byte is 11, it's packed as this 1-byte
# representation; otherwise, if XX in the first byte is 00, it's packed as
# "CLL", ie. 1 byte and 2 32-bit "longs" in perl pack format.

# Savings: roughly halves size of toks db, at the cost of a ~10% slowdown.

use constant FORMAT_FLAG	=> 0xc0;	# 11000000
  use constant ONE_BYTE_FORMAT	=> 0xc0;	# 11000000
  use constant TWO_LONGS_FORMAT	=> 0x00;	# 00000000

use constant ONE_BYTE_SSS_BITS	=> 0x38;	# 00111000
use constant ONE_BYTE_HHH_BITS	=> 0x07;	# 00000111

sub tok_unpack {
  my ($packed, $atime) = unpack("CS", $_[0] || 0);

  if (($packed & FORMAT_FLAG) == ONE_BYTE_FORMAT) {
    return (($packed & ONE_BYTE_SSS_BITS) >> 3,
		$packed & ONE_BYTE_HHH_BITS,
		$atime || 0);
  }
  elsif (($packed & FORMAT_FLAG) == TWO_LONGS_FORMAT) {
    my ($packed, $ts, $th, $atime) = unpack("CLLS", $_[0] || 0);
    return ($ts || 0, $th || 0, $atime || 0);
  }
  # other formats would go here...
  else {
    warn "unknown packing format for Bayes db, please re-learn: $packed";
    return (0, 0, 0);
  }
}

sub tok_pack {
  my ($ts, $th, $atime) = @_;
  $ts ||= 0; $th ||= 0; $atime ||= 0;
  if ($ts < 8 && $th < 8) {
    return pack ("CS", ONE_BYTE_FORMAT | ($ts << 3) | $th, $atime);
  } else {
    return pack ("CLLS", TWO_LONGS_FORMAT, $ts, $th, $atime);
  }
}

# 2-byte time format: expiry is after the time_t epoch, so time_t calculations
# will fail before this will.
use constant ATIME_EPOCH_START	=> 1038000000;  # Fri Nov 22 21:20:00 2002
use constant ATIME_GRANULARITY  => 21600;	# 6 hours

sub atime_to_time_t {
  my ($self, $atime) = @_;
  return ($atime * ATIME_GRANULARITY) + ATIME_EPOCH_START;
}

sub time_t_to_atime {
  my ($self, $tt) = @_;
  return int (($tt - ATIME_EPOCH_START) / ATIME_GRANULARITY);
}

###########################################################################

sub dbg { Mail::SpamAssassin::dbg (@_); }
sub sa_die { Mail::SpamAssassin::sa_die (@_); }

1;
