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

package Mail::SpamAssassin::BayesStore::DBM;

use strict;
use warnings;
use bytes;
use re 'taint';

use Fcntl;
use Errno qw(EBADF);
use File::Basename;
use File::Spec;
use File::Path;

BEGIN {
  eval { require Digest::SHA; import Digest::SHA qw(sha1); 1 }
  or do { require Digest::SHA1; import Digest::SHA1 qw(sha1) }
}

use Mail::SpamAssassin;
use Mail::SpamAssassin::Util qw(untaint_var am_running_on_windows);
use Mail::SpamAssassin::BayesStore;
use Mail::SpamAssassin::Logger;

use constant MAGIC_RE    => qr/^\015\001\007\011\003/;

use vars qw{
  @ISA
  @DBNAMES
  $NSPAM_MAGIC_TOKEN $NHAM_MAGIC_TOKEN $LAST_EXPIRE_MAGIC_TOKEN $LAST_JOURNAL_SYNC_MAGIC_TOKEN
  $NTOKENS_MAGIC_TOKEN $OLDEST_TOKEN_AGE_MAGIC_TOKEN $LAST_EXPIRE_REDUCE_MAGIC_TOKEN
  $RUNNING_EXPIRE_MAGIC_TOKEN $DB_VERSION_MAGIC_TOKEN $LAST_ATIME_DELTA_MAGIC_TOKEN
  $NEWEST_TOKEN_AGE_MAGIC_TOKEN
};

@ISA = qw( Mail::SpamAssassin::BayesStore );

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

# These are the magic tokens we use to track stuff in the DB.
# The format is '^M^A^G^I^C' followed by any string you want.
# None of the control chars will be in a real token.
$DB_VERSION_MAGIC_TOKEN		= "\015\001\007\011\003DBVERSION";
$LAST_ATIME_DELTA_MAGIC_TOKEN	= "\015\001\007\011\003LASTATIMEDELTA";
$LAST_EXPIRE_MAGIC_TOKEN	= "\015\001\007\011\003LASTEXPIRE";
$LAST_EXPIRE_REDUCE_MAGIC_TOKEN	= "\015\001\007\011\003LASTEXPIREREDUCE";
$LAST_JOURNAL_SYNC_MAGIC_TOKEN	= "\015\001\007\011\003LASTJOURNALSYNC";
$NEWEST_TOKEN_AGE_MAGIC_TOKEN	= "\015\001\007\011\003NEWESTAGE";
$NHAM_MAGIC_TOKEN		= "\015\001\007\011\003NHAM";
$NSPAM_MAGIC_TOKEN		= "\015\001\007\011\003NSPAM";
$NTOKENS_MAGIC_TOKEN		= "\015\001\007\011\003NTOKENS";
$OLDEST_TOKEN_AGE_MAGIC_TOKEN	= "\015\001\007\011\003OLDESTAGE";
$RUNNING_EXPIRE_MAGIC_TOKEN	= "\015\001\007\011\003RUNNINGEXPIRE";

sub HAS_DBM_MODULE {
  my ($self) = @_;
  if (exists($self->{has_dbm_module})) {
    return $self->{has_dbm_module};
  }
  $self->{has_dbm_module} = eval { require DB_File; };
}

sub DBM_MODULE {
  return "DB_File";
}

# Possible file extensions used by the kinds of database files DB_File
# might create.  We need these so we can create a new file and rename
# it into place.
sub DB_EXTENSIONS {
  return ('', '.db');
}

###########################################################################

sub new {
  my $class = shift;
  $class = ref($class) || $class;

  my $self = $class->SUPER::new(@_);

  $self->{supported_db_version} = 3;

  $self->{already_tied} = 0;
  $self->{is_locked} = 0;
  $self->{string_to_journal} = '';

  $self;
}

###########################################################################

sub tie_db_readonly {
  my ($self) = @_;

  if (!$self->HAS_DBM_MODULE) {
    dbg("bayes: %s module not installed, cannot use bayes", $self->DBM_MODULE);
    return 0;
  }

  # return if we've already tied to the db's, using the same mode
  # (locked/unlocked) as before.
  return 1 if ($self->{already_tied} && $self->{is_locked} == 0);

  my $main = $self->{bayes}->{main};
  if (!defined($main->{conf}->{bayes_path})) {
    dbg("bayes: bayes_path not defined");
    return 0;
  }

  $self->read_db_configs();

  my $path = $main->sed_path($main->{conf}->{bayes_path});

  my $found = 0;
  for my $ext ($self->DB_EXTENSIONS) {
    if (-f $path.'_toks'.$ext) {
      $found = 1;
      last;
    }
  }

  if (!$found) {
    dbg("bayes: no dbs present, cannot tie DB R/O: %s", $path.'_toks');
    return 0;
  }

  foreach my $dbname (@DBNAMES) {
    my $name = $path.'_'.$dbname;
    my $db_var = 'db_'.$dbname;
    dbg("bayes: tie-ing to DB file R/O $name");

    # Bug 6901, [rt.cpan.org #83060]
    # DB_File: Repeated tie to the same hash with no untie causes corruption
    untie %{$self->{$db_var}};  # has no effect if the variable is not tied

    if (!tie %{$self->{$db_var}}, $self->DBM_MODULE, $name, O_RDONLY,
		 (oct($main->{conf}->{bayes_file_mode}) & 0666))
    {
      # bug 2975: it's acceptable for the db_seen to not be present,
      # to allow it to be recycled.  if that's the case, just create
      # a new, empty one. we don't need to lock it, since we won't
      # be writing to it; let the R/W api deal with that case.

      if ($dbname eq 'seen') {
        # Bug 6901, [rt.cpan.org #83060]
        untie %{$self->{$db_var}};  # has no effect if the variable is not tied
        tie %{$self->{$db_var}}, $self->DBM_MODULE, $name, O_RDWR|O_CREAT,
                    (oct($main->{conf}->{bayes_file_mode}) & 0666)
          or goto failed_to_tie;
      }
      else {
        goto failed_to_tie;
      }
    }
  }

  $self->{db_version} = ($self->get_storage_variables())[6];
  dbg("bayes: found bayes db version %s", $self->{db_version});

  # If the DB version is one we don't understand, abort!
  if ($self->_check_db_version() != 0) {
    warn("bayes: bayes db version ".$self->{db_version}." is not able to be used, aborting!");
    $self->untie_db();
    return 0;
  }

  $self->{already_tied} = 1;
  return 1;

failed_to_tie:
  warn "bayes: cannot open bayes databases ${path}_* R/O: tie failed: $!\n";
  foreach my $dbname (@DBNAMES) {
    my $db_var = 'db_'.$dbname;
    next unless exists $self->{$db_var};
    dbg("bayes: untie-ing DB file $dbname");
    untie %{$self->{$db_var}};
  }

  return 0;
}

# tie() to the databases, read-write and locked.  Any callers of
# this should ensure they call untie_db() afterwards!
#
sub tie_db_writable {
  my ($self) = @_;

  if (!$self->HAS_DBM_MODULE) {
    dbg("bayes: %s module not installed, cannot use bayes", $self->DBM_MODULE);
    return 0;
  }

  # Useful shortcut ...
  my $main = $self->{bayes}->{main};

  # if we've already tied the db's using the same mode
  # (locked/unlocked) as we want now, freshen the lock and return.
  if ($self->{already_tied} && $self->{is_locked} == 1) {
    $main->{locker}->refresh_lock($self->{locked_file});
    return 1;
  }

  if (!defined($main->{conf}->{bayes_path})) {
    dbg("bayes: bayes_path not defined");
    return 0;
  }

  $self->read_db_configs();

  my $path = $main->sed_path($main->{conf}->{bayes_path});

  my $found = 0;
  for my $ext ($self->DB_EXTENSIONS) {
    if (-f $path.'_toks'.$ext) {
      $found = 1;
      last;
    }
  }

  my $parentdir = dirname($path);
  if (!-d $parentdir) {
    # run in an eval(); if mkpath has no perms, it calls die()
    eval {
      mkpath($parentdir, 0, (oct($main->{conf}->{bayes_file_mode}) & 0777));
    };
  }

  my $tout;
  if ($main->{learn_wait_for_lock}) {
    $tout = 300;       # TODO: Dan to write better lock code
  } else {
    $tout = 10;
  }
  if ($main->{locker}->safe_lock($path, $tout, $main->{conf}->{bayes_file_mode}))
  {
    $self->{locked_file} = $path;
    $self->{is_locked} = 1;
  } else {
    warn "bayes: cannot open bayes databases ${path}_* R/W: lock failed: $!\n";
    return 0;
  }

  my $umask = umask 0;
  foreach my $dbname (@DBNAMES) {
    my $name = $path.'_'.$dbname;
    my $db_var = 'db_'.$dbname;
    dbg("bayes: tie-ing to DB file R/W $name");

    ($self->DBM_MODULE eq 'DB_File') and
         Mail::SpamAssassin::Util::avoid_db_file_locking_bug ($name);

    # Bug 6901, [rt.cpan.org #83060]
    untie %{$self->{$db_var}};  # has no effect if the variable is not tied
    tie %{$self->{$db_var}}, $self->DBM_MODULE, $name, O_RDWR|O_CREAT,
		 (oct($main->{conf}->{bayes_file_mode}) & 0666)
       or goto failed_to_tie;
  }
  umask $umask;

  # set our cache to what version DB we're using
  $self->{db_version} = ($self->get_storage_variables())[6];
  # don't bother printing this unless found since it would be bogus anyway
  dbg("bayes: found bayes db version %s", $self->{db_version}) if $found;

  # figure out if we can read the current DB and if we need to do a
  # DB version update and do it if necessary if either has a problem,
  # fail immediately
  #
  if ($found && !$self->_upgrade_db()) {
    $self->untie_db();
    return 0;
  }
  elsif (!$found) { # new DB, make sure we know that ...
    $self->{db_version} = $self->{db_toks}->{$DB_VERSION_MAGIC_TOKEN} = $self->DB_VERSION;
    $self->{db_toks}->{$NTOKENS_MAGIC_TOKEN} = 0; # no tokens in the db ...
    dbg("bayes: new db, set db version %s and 0 tokens", $self->{db_version});
  }

  $self->{already_tied} = 1;
  return 1;

failed_to_tie:
  my $err = $!;
  umask $umask;

  foreach my $dbname (@DBNAMES) {
    my $db_var = 'db_'.$dbname;
    next unless exists $self->{$db_var};
    dbg("bayes: untie-ing DB file $dbname");
    untie %{$self->{$db_var}};
  }       

  if ($self->{is_locked}) {
    $self->{bayes}->{main}->{locker}->safe_unlock($self->{locked_file});
    $self->{is_locked} = 0;
  }
  warn "bayes: cannot open bayes databases ${path}_* R/W: tie failed: $err\n";
  return 0;
}

# Do we understand how to deal with this DB version?
sub _check_db_version {
  my ($self) = @_;

  # return -1 if older, 0 if current, 1 if newer
  return $self->{db_version} <=> $self->DB_VERSION;
}

# Check to see if we need to upgrade the DB, and do so if necessary
sub _upgrade_db {
  my ($self) = @_;

  my $verschk = $self->_check_db_version();
  my $res = 0; # used later on for tie() checks
  my $umask; # used later for umask modifications

  # If the DB is the latest version, no problem.
  return 1 if ($verschk == 0);

  # If the DB is a newer version that we know what to do with ... abort!
  if ($verschk == 1) {
    warn("bayes: bayes db version ".$self->{db_version}." is newer than we understand, aborting!");
    return 0;
  }

  # If the current DB version is lower than the new version, upgrade!
  # Do conversions in order so we can go 1 -> 3, make sure to update
  #   $self->{db_version} along the way

  dbg("bayes: detected bayes db format %s, upgrading", $self->{db_version});

  # since DB_File will not shrink a database (!!), we need to *create*
  # a new one instead.
  my $main = $self->{bayes}->{main};
  my $path = $main->sed_path($main->{conf}->{bayes_path});
  my $name = $path.'_toks';

  # older version's journal files are likely not in the same format as the new ones, so remove it.
  my $jpath = $self->_get_journal_filename();
  if (-f $jpath) {
    dbg("bayes: old journal file found, removing");
    warn "bayes: couldn't remove $jpath: $!" if (!unlink $jpath);
  }

  if ($self->{db_version} < 2) {
    dbg("bayes: upgrading database format from v%s to v2", $self->{db_version});
    $self->set_running_expire_tok();

    my ($DB_NSPAM_MAGIC_TOKEN, $DB_NHAM_MAGIC_TOKEN, $DB_NTOKENS_MAGIC_TOKEN);
    my ($DB_OLDEST_TOKEN_AGE_MAGIC_TOKEN, $DB_LAST_EXPIRE_MAGIC_TOKEN);

    # Magic tokens for version 0, defined as '**[A-Z]+'
    if ($self->{db_version} == 0) {
      $DB_NSPAM_MAGIC_TOKEN			= '**NSPAM';
      $DB_NHAM_MAGIC_TOKEN			= '**NHAM';
      $DB_NTOKENS_MAGIC_TOKEN			= '**NTOKENS';
      #$DB_OLDEST_TOKEN_AGE_MAGIC_TOKEN		= '**OLDESTAGE';
      #$DB_LAST_EXPIRE_MAGIC_TOKEN		= '**LASTEXPIRE';
      #$DB_SCANCOUNT_BASE_MAGIC_TOKEN		= '**SCANBASE';
      #$DB_RUNNING_EXPIRE_MAGIC_TOKEN		= '**RUNNINGEXPIRE';
    }
    else {
      $DB_NSPAM_MAGIC_TOKEN			= "\015\001\007\011\003NSPAM";
      $DB_NHAM_MAGIC_TOKEN			= "\015\001\007\011\003NHAM";
      $DB_NTOKENS_MAGIC_TOKEN			= "\015\001\007\011\003NTOKENS";
      #$DB_OLDEST_TOKEN_AGE_MAGIC_TOKEN		= "\015\001\007\011\003OLDESTAGE";
      #$DB_LAST_EXPIRE_MAGIC_TOKEN		= "\015\001\007\011\003LASTEXPIRE";
      #$DB_SCANCOUNT_BASE_MAGIC_TOKEN		= "\015\001\007\011\003SCANBASE";
      #$DB_RUNNING_EXPIRE_MAGIC_TOKEN		= "\015\001\007\011\003RUNNINGEXPIRE";
    }

    # remember when we started ...
    my $started = time;
    my $newatime = $started;

    # use O_EXCL to avoid races (bonus paranoia, since we should be locked
    # anyway)
    my %new_toks;
    $umask = umask 0;

    $res = tie %new_toks, $self->DBM_MODULE, "${name}.new",
             O_RDWR|O_CREAT|O_EXCL,
             (oct($main->{conf}->{bayes_file_mode}) & 0666);
    umask $umask;
    return 0 unless $res;
    undef $res;

    # add the magic tokens to the new db.
    $new_toks{$NSPAM_MAGIC_TOKEN} = $self->{db_toks}->{$DB_NSPAM_MAGIC_TOKEN};
    $new_toks{$NHAM_MAGIC_TOKEN} = $self->{db_toks}->{$DB_NHAM_MAGIC_TOKEN};
    $new_toks{$NTOKENS_MAGIC_TOKEN} = $self->{db_toks}->{$DB_NTOKENS_MAGIC_TOKEN};
    $new_toks{$DB_VERSION_MAGIC_TOKEN} = 2; # we're now a DB version 2 file
    $new_toks{$OLDEST_TOKEN_AGE_MAGIC_TOKEN} = $newatime;
    $new_toks{$LAST_EXPIRE_MAGIC_TOKEN} = $newatime;
    $new_toks{$NEWEST_TOKEN_AGE_MAGIC_TOKEN} = $newatime;
    $new_toks{$LAST_JOURNAL_SYNC_MAGIC_TOKEN} = $newatime;
    $new_toks{$LAST_ATIME_DELTA_MAGIC_TOKEN} = 0;
    $new_toks{$LAST_EXPIRE_REDUCE_MAGIC_TOKEN} = 0;

    # deal with the data tokens
    my ($tok, $packed);
    my $count = 0;
    while (($tok, $packed) = each %{$self->{db_toks}}) {
      next if ($tok =~ /^(?:\*\*[A-Z]+$|\015\001\007\011\003)/); # skip magic tokens

      my ($ts, $th, $atime) = $self->tok_unpack($packed);
      $new_toks{$tok} = $self->tok_pack($ts, $th, $newatime);

      # Refresh the lock every so often...
      if (($count++ % 1000) == 0) {
        $self->set_running_expire_tok();
      }
    }


    # now untie so we can do renames
    untie %{$self->{db_toks}};
    untie %new_toks;

    # This is the critical phase (moving files around), so don't allow
    # it to be interrupted.
    local $SIG{'INT'} = 'IGNORE';
    local $SIG{'TERM'} = 'IGNORE';
    local $SIG{'HUP'} = 'IGNORE' if !am_running_on_windows();

    # older versions used scancount, so kill the stupid little file ...
    my $msgc = $path.'_msgcount';
    if (-f $msgc) {
      dbg("bayes: old msgcount file found, removing");
      if (!unlink $msgc) {
        warn "bayes: couldn't remove $msgc: $!";
      }
    }

    # now rename in the new one.  Try several extensions
    for my $ext ($self->DB_EXTENSIONS) {
      my $newf = $name.'.new'.$ext;
      my $oldf = $name.$ext;
      next unless (-f $newf);
      if (!rename ($newf, $oldf)) {
        warn "bayes: rename $newf to $oldf failed: $!\n";
        return 0;
      }
    }

    # re-tie to the new db in read-write mode ...
    $umask = umask 0;
    # Bug 6901, [rt.cpan.org #83060]
    untie %{$self->{db_toks}};  # has no effect if the variable is not tied
    $res = tie %{$self->{db_toks}}, $self->DBM_MODULE, $name, O_RDWR|O_CREAT,
	 (oct($main->{conf}->{bayes_file_mode}) & 0666);
    umask $umask;
    return 0 unless $res;
    undef $res;

    dbg("bayes: upgraded database format from v%s to v2 in %d seconds",
        $self->{db_version}, time - $started);
    $self->{db_version} = 2; # need this for other functions which check
  }

  # Version 3 of the database converts all existing tokens to SHA1 hashes
  if ($self->{db_version} == 2) {
    dbg("bayes: upgrading database format from v%s to v3", $self->{db_version});
    $self->set_running_expire_tok();

    my $DB_NSPAM_MAGIC_TOKEN		  = "\015\001\007\011\003NSPAM";
    my $DB_NHAM_MAGIC_TOKEN		  = "\015\001\007\011\003NHAM";
    my $DB_NTOKENS_MAGIC_TOKEN		  = "\015\001\007\011\003NTOKENS";
    my $DB_OLDEST_TOKEN_AGE_MAGIC_TOKEN	  = "\015\001\007\011\003OLDESTAGE";
    my $DB_LAST_EXPIRE_MAGIC_TOKEN	  = "\015\001\007\011\003LASTEXPIRE";
    my $DB_NEWEST_TOKEN_AGE_MAGIC_TOKEN	  = "\015\001\007\011\003NEWESTAGE";
    my $DB_LAST_JOURNAL_SYNC_MAGIC_TOKEN  = "\015\001\007\011\003LASTJOURNALSYNC";
    my $DB_LAST_ATIME_DELTA_MAGIC_TOKEN	  = "\015\001\007\011\003LASTATIMEDELTA";
    my $DB_LAST_EXPIRE_REDUCE_MAGIC_TOKEN = "\015\001\007\011\003LASTEXPIREREDUCE";

    # remember when we started ...
    my $started = time;

    # use O_EXCL to avoid races (bonus paranoia, since we should be locked
    # anyway)
    my %new_toks;
    $umask = umask 0;
    $res = tie %new_toks, $self->DBM_MODULE, "${name}.new", O_RDWR|O_CREAT|O_EXCL,
          (oct($main->{conf}->{bayes_file_mode}) & 0666);
    umask $umask;
    return 0 unless $res;
    undef $res;

    # add the magic tokens to the new db.
    $new_toks{$NSPAM_MAGIC_TOKEN} = $self->{db_toks}->{$DB_NSPAM_MAGIC_TOKEN};
    $new_toks{$NHAM_MAGIC_TOKEN} = $self->{db_toks}->{$DB_NHAM_MAGIC_TOKEN};
    $new_toks{$NTOKENS_MAGIC_TOKEN} = $self->{db_toks}->{$DB_NTOKENS_MAGIC_TOKEN};
    $new_toks{$DB_VERSION_MAGIC_TOKEN} = 3; # we're now a DB version 3 file
    $new_toks{$OLDEST_TOKEN_AGE_MAGIC_TOKEN} = $self->{db_toks}->{$DB_OLDEST_TOKEN_AGE_MAGIC_TOKEN};
    $new_toks{$LAST_EXPIRE_MAGIC_TOKEN} = $self->{db_toks}->{$DB_LAST_EXPIRE_MAGIC_TOKEN};
    $new_toks{$NEWEST_TOKEN_AGE_MAGIC_TOKEN} = $self->{db_toks}->{$DB_NEWEST_TOKEN_AGE_MAGIC_TOKEN};
    $new_toks{$LAST_JOURNAL_SYNC_MAGIC_TOKEN} = $self->{db_toks}->{$DB_LAST_JOURNAL_SYNC_MAGIC_TOKEN};
    $new_toks{$LAST_ATIME_DELTA_MAGIC_TOKEN} = $self->{db_toks}->{$DB_LAST_ATIME_DELTA_MAGIC_TOKEN};
    $new_toks{$LAST_EXPIRE_REDUCE_MAGIC_TOKEN} =$self->{db_toks}->{$DB_LAST_EXPIRE_REDUCE_MAGIC_TOKEN};

    # deal with the data tokens
    my $count = 0;
    while (my ($tok, $packed) = each %{$self->{db_toks}}) {
      next if ($tok =~ /^\015\001\007\011\003/); # skip magic tokens
      my $tok_hash = substr(sha1($tok), -5);
      $new_toks{$tok_hash} = $packed;

      # Refresh the lock every so often...
      if (($count++ % 1000) == 0) {
        $self->set_running_expire_tok();
      }
    }

    # now untie so we can do renames
    untie %{$self->{db_toks}};
    untie %new_toks;

    # This is the critical phase (moving files around), so don't allow
    # it to be interrupted.
    local $SIG{'INT'} = 'IGNORE';
    local $SIG{'TERM'} = 'IGNORE';
    local $SIG{'HUP'} = 'IGNORE' if !am_running_on_windows();

    # now rename in the new one.  Try several extensions
    for my $ext ($self->DB_EXTENSIONS) {
      my $newf = $name.'.new'.$ext;
      my $oldf = $name.$ext;
      next unless (-f $newf);
      if (!rename($newf, $oldf)) {
        warn "bayes: rename $newf to $oldf failed: $!\n";
        return 0;
      }
    }

    # re-tie to the new db in read-write mode ...
    $umask = umask 0;
    # Bug 6901, [rt.cpan.org #83060]
    untie %{$self->{db_toks}};  # has no effect if the variable is not tied
    $res = tie %{$self->{db_toks}}, $self->DBM_MODULE, $name, O_RDWR|O_CREAT,
	 (oct ($main->{conf}->{bayes_file_mode}) & 0666);
    umask $umask;
    return 0 unless $res;
    undef $res;

    dbg("bayes: upgraded database format from v%s to v3 in %d seconds",
        $self->{db_version}, time - $started);

    $self->{db_version} = 3; # need this for other functions which check
  }

  # if ($self->{db_version} == 3) {
  #   ...
  #   $self->{db_version} = 4; # need this for other functions which check
  # }
  # ... and so on.

  return 1;
}

###########################################################################

sub untie_db {
  my $self = shift;

  return if (!$self->{already_tied});

  dbg("bayes: untie-ing");

  foreach my $dbname (@DBNAMES) {
    my $db_var = 'db_'.$dbname;

    if (exists $self->{$db_var}) {
      # dbg("bayes: untie-ing $db_var");
      untie %{$self->{$db_var}};
      delete $self->{$db_var};
    }
  }

  if ($self->{is_locked}) {
    dbg("bayes: files locked, now unlocking lock");
    $self->{bayes}->{main}->{locker}->safe_unlock ($self->{locked_file});
    $self->{is_locked} = 0;
  }

  $self->{already_tied} = 0;
  $self->{db_version} = undef;
}

###########################################################################

sub calculate_expire_delta {
  my ($self, $newest_atime, $start, $max_expire_mult) = @_;

  my %delta;  # use a hash since an array is going to be very sparse

  # do the first pass, figure out atime delta
  my ($tok, $packed);
  while (($tok, $packed) = each %{$self->{db_toks}}) {
    next if ($tok =~ MAGIC_RE); # skip magic tokens
    
    my ($ts, $th, $atime) = $self->tok_unpack ($packed);

    # Go through from $start * 1 to $start * 512, mark how many tokens
    # we would expire
    my $token_age = $newest_atime - $atime;
    for (my $i = 1; $i <= $max_expire_mult; $i<<=1) {
      if ($token_age >= $start * $i) {
        $delta{$i}++;
      }
      else {
        # If the token age is less than the expire delta, it'll be
        # less for all upcoming checks too, so abort early.
        last;
      }
    }
  }
  return %delta;
}

###########################################################################

sub token_expiration {
  my ($self, $opts, $newdelta, @vars) = @_;

  my $deleted = 0;
  my $kept = 0;
  my $num_hapaxes = 0;
  my $num_lowfreq = 0;

  # since DB_File will not shrink a database (!!), we need to *create*
  # a new one instead.
  my $main = $self->{bayes}->{main};
  my $path = $main->sed_path($main->{conf}->{bayes_path});

  # use a temporary PID-based suffix just in case another one was
  # created previously by an interrupted expire
  my $tmpsuffix = "expire$$";
  my $tmpdbname = $path.'_toks.'.$tmpsuffix;

  # clean out any leftover db copies from previous runs
  for my $ext ($self->DB_EXTENSIONS) { unlink ($tmpdbname.$ext); }

  # use O_EXCL to avoid races (bonus paranoia, since we should be locked
  # anyway)
  my %new_toks;
  my $umask = umask 0;
  tie %new_toks, $self->DBM_MODULE, $tmpdbname, O_RDWR|O_CREAT|O_EXCL,
              (oct ($main->{conf}->{bayes_file_mode}) & 0666);
  umask $umask;
  my $oldest;

  my $showdots = $opts->{showdots};
  if ($showdots) { print STDERR "\n"; }

  # We've chosen a new atime delta if we've gotten here, so record it
  # for posterity.
  $new_toks{$LAST_ATIME_DELTA_MAGIC_TOKEN} = $newdelta;

  # Figure out how old is too old...
  my $too_old = $vars[10] - $newdelta; # tooold = newest - delta

  # Go ahead and do the move to new db/expire run now ...
  my ($tok, $packed);
  while (($tok, $packed) = each %{$self->{db_toks}}) {
    next if ($tok =~ MAGIC_RE); # skip magic tokens

    my ($ts, $th, $atime) = $self->tok_unpack ($packed);

    if ($atime < $too_old) {
      $deleted++;
    }
    else {
      # if token atime > newest, reset to newest ...
      if ($atime > $vars[10]) {
        $atime = $vars[10];
      }

      $new_toks{$tok} = $self->tok_pack ($ts, $th, $atime); $kept++;
      if (!defined($oldest) || $atime < $oldest) { $oldest = $atime; }
      if ($ts + $th == 1) {
	$num_hapaxes++;
      } elsif ($ts < 8 && $th < 8) {
	$num_lowfreq++;
      }
    }

    if ((($kept + $deleted) % 1000) == 0) {
      if ($showdots) { print STDERR "."; }
      $self->set_running_expire_tok();
    }
  }

  # and add the magic tokens.  don't add the expire_running token.
  $new_toks{$DB_VERSION_MAGIC_TOKEN} = $self->DB_VERSION;

  # We haven't changed messages of each type seen, so just copy over.
  $new_toks{$NSPAM_MAGIC_TOKEN} = $vars[1];
  $new_toks{$NHAM_MAGIC_TOKEN} = $vars[2];

  # We magically haven't removed the newest token, so just copy that value over.
  $new_toks{$NEWEST_TOKEN_AGE_MAGIC_TOKEN} = $vars[10];

  # The rest of these have been modified, so replace as necessary.
  $new_toks{$NTOKENS_MAGIC_TOKEN} = $kept;
  $new_toks{$LAST_EXPIRE_MAGIC_TOKEN} = time();
  $new_toks{$OLDEST_TOKEN_AGE_MAGIC_TOKEN} = $oldest;
  $new_toks{$LAST_EXPIRE_REDUCE_MAGIC_TOKEN} = $deleted;

  # Sanity check: if we expired too many tokens, abort!
  if ($kept < 100000) {
    dbg("bayes: token expiration would expire too many tokens, aborting");
    # set the magic tokens appropriately
    # make sure the next expire run does a first pass
    $self->{db_toks}->{$LAST_EXPIRE_MAGIC_TOKEN} = time();
    $self->{db_toks}->{$LAST_EXPIRE_REDUCE_MAGIC_TOKEN} = 0;
    $self->{db_toks}->{$LAST_ATIME_DELTA_MAGIC_TOKEN} = 0;

    # remove the new DB
    untie %new_toks;
    for my $ext ($self->DB_EXTENSIONS) { unlink ($tmpdbname.$ext); }

    # reset the results for the return
    $kept = $vars[3];
    $deleted = 0;
    $num_hapaxes = 0;
    $num_lowfreq = 0;
  }
  else {
    # now untie so we can do renames
    untie %{$self->{db_toks}};
    untie %new_toks;

    # This is the critical phase (moving files around), so don't allow
    # it to be interrupted.  Scope the signal changes.
    {
      local $SIG{'INT'} = 'IGNORE';
      local $SIG{'TERM'} = 'IGNORE';
      local $SIG{'HUP'} = 'IGNORE' if !am_running_on_windows();

      # now rename in the new one.  Try several extensions
      for my $ext ($self->DB_EXTENSIONS) {
        my $newf = $tmpdbname.$ext;
        my $oldf = $path.'_toks'.$ext;
        next unless (-f $newf);
        if (!rename ($newf, $oldf)) {
	  warn "bayes: rename $newf to $oldf failed: $!\n";
        }
      }
    }
  }

  # Call untie_db() so we unlock correctly.
  $self->untie_db();

  return ($kept, $deleted, $num_hapaxes, $num_lowfreq);
}

###########################################################################

# Is a sync due?
sub sync_due {
  my ($self) = @_;

  # don't bother doing old db versions
  return 0 if ($self->{db_version} < $self->DB_VERSION);

  my $conf = $self->{bayes}->{main}->{conf};
  return 0 if ($conf->{bayes_journal_max_size} == 0);

  my @vars = $self->get_storage_variables();
  dbg("bayes: DB journal sync: last sync: %s", $vars[7]);

  ## Ok, should we do a sync?

  # Not if the journal file doesn't exist, it's not a file, or it's 0
  # bytes long.
  return 0 unless (stat($self->_get_journal_filename()) && -f _);

  # Yes if the file size is larger than the specified maximum size.
  return 1 if (-s _ > $conf->{bayes_journal_max_size});

  # Yes there has been a sync before, and if it's been at least a day
  # since that sync.
  return 1 if (($vars[7] > 0) && (time - $vars[7] > 86400));

  # No, I guess not.
  return 0;
}

###########################################################################
# db_seen reading APIs

sub seen_get {
  my ($self, $msgid) = @_;
  $self->{db_seen}->{$msgid};
}

sub seen_put {
  my ($self, $msgid, $seen) = @_;

  if ($self->{bayes}->{main}->{learn_to_journal}) {
    $self->defer_update ("m $seen $msgid");
  }
  else {
    $self->_seen_put_direct($msgid, $seen);
  }
}
sub _seen_put_direct {
  my ($self, $msgid, $seen) = @_;
  $self->{db_seen}->{$msgid} = $seen;
}

sub seen_delete {
  my ($self, $msgid) = @_;

  if ($self->{bayes}->{main}->{learn_to_journal}) {
    $self->defer_update ("m f $msgid");
  }
  else {
    $self->_seen_delete_direct($msgid);
  }
}
sub _seen_delete_direct {
  my ($self, $msgid) = @_;
  delete $self->{db_seen}->{$msgid};
}

###########################################################################
# db reading APIs

sub tok_get {
  my ($self, $tok) = @_;
  $self->tok_unpack ($self->{db_toks}->{$tok});
}
 
sub tok_get_all {
  my ($self, @tokens) = @_;

  my @tokensdata;
  foreach my $token (@tokens) {
    my ($tok_spam, $tok_ham, $atime) = $self->tok_unpack($self->{db_toks}->{$token});
    push(@tokensdata, [$token, $tok_spam, $tok_ham, $atime]);
  }
  return \@tokensdata;
}

# return the magic tokens in a specific order:
# 0: scan count base
# 1: number of spam
# 2: number of ham
# 3: number of tokens in db
# 4: last expire atime
# 5: oldest token in db atime
# 6: db version value
# 7: last journal sync
# 8: last atime delta
# 9: last expire reduction count
# 10: newest token in db atime
#
sub get_storage_variables {
  my ($self) = @_;
  my @values;

  my $db_ver = $self->{db_toks}->{$DB_VERSION_MAGIC_TOKEN};

  if (!$db_ver || $db_ver =~ /\D/) { $db_ver = 0; }

  if ($db_ver >= 2) {
    my $DB2_LAST_ATIME_DELTA_MAGIC_TOKEN	= "\015\001\007\011\003LASTATIMEDELTA";
    my $DB2_LAST_EXPIRE_MAGIC_TOKEN		= "\015\001\007\011\003LASTEXPIRE";
    my $DB2_LAST_EXPIRE_REDUCE_MAGIC_TOKEN	= "\015\001\007\011\003LASTEXPIREREDUCE";
    my $DB2_LAST_JOURNAL_SYNC_MAGIC_TOKEN	= "\015\001\007\011\003LASTJOURNALSYNC";
    my $DB2_NEWEST_TOKEN_AGE_MAGIC_TOKEN	= "\015\001\007\011\003NEWESTAGE";
    my $DB2_NHAM_MAGIC_TOKEN			= "\015\001\007\011\003NHAM";
    my $DB2_NSPAM_MAGIC_TOKEN			= "\015\001\007\011\003NSPAM";
    my $DB2_NTOKENS_MAGIC_TOKEN			= "\015\001\007\011\003NTOKENS";
    my $DB2_OLDEST_TOKEN_AGE_MAGIC_TOKEN	= "\015\001\007\011\003OLDESTAGE";
    my $DB2_RUNNING_EXPIRE_MAGIC_TOKEN		= "\015\001\007\011\003RUNNINGEXPIRE";

    @values = (
      0,
      $self->{db_toks}->{$DB2_NSPAM_MAGIC_TOKEN},
      $self->{db_toks}->{$DB2_NHAM_MAGIC_TOKEN},
      $self->{db_toks}->{$DB2_NTOKENS_MAGIC_TOKEN},
      $self->{db_toks}->{$DB2_LAST_EXPIRE_MAGIC_TOKEN},
      $self->{db_toks}->{$DB2_OLDEST_TOKEN_AGE_MAGIC_TOKEN},
      $db_ver,
      $self->{db_toks}->{$DB2_LAST_JOURNAL_SYNC_MAGIC_TOKEN},
      $self->{db_toks}->{$DB2_LAST_ATIME_DELTA_MAGIC_TOKEN},
      $self->{db_toks}->{$DB2_LAST_EXPIRE_REDUCE_MAGIC_TOKEN},
      $self->{db_toks}->{$DB2_NEWEST_TOKEN_AGE_MAGIC_TOKEN},
    );
  }
  elsif ($db_ver == 0) {
    my $DB0_NSPAM_MAGIC_TOKEN = '**NSPAM';
    my $DB0_NHAM_MAGIC_TOKEN = '**NHAM';
    my $DB0_OLDEST_TOKEN_AGE_MAGIC_TOKEN = '**OLDESTAGE';
    my $DB0_LAST_EXPIRE_MAGIC_TOKEN = '**LASTEXPIRE';
    my $DB0_NTOKENS_MAGIC_TOKEN = '**NTOKENS';
    my $DB0_SCANCOUNT_BASE_MAGIC_TOKEN = '**SCANBASE';

    @values = (
      $self->{db_toks}->{$DB0_SCANCOUNT_BASE_MAGIC_TOKEN},
      $self->{db_toks}->{$DB0_NSPAM_MAGIC_TOKEN},
      $self->{db_toks}->{$DB0_NHAM_MAGIC_TOKEN},
      $self->{db_toks}->{$DB0_NTOKENS_MAGIC_TOKEN},
      $self->{db_toks}->{$DB0_LAST_EXPIRE_MAGIC_TOKEN},
      $self->{db_toks}->{$DB0_OLDEST_TOKEN_AGE_MAGIC_TOKEN},
      0,
      0,
      0,
      0,
      0,
    );
  }
  elsif ($db_ver == 1) {
    my $DB1_NSPAM_MAGIC_TOKEN			= "\015\001\007\011\003NSPAM";
    my $DB1_NHAM_MAGIC_TOKEN			= "\015\001\007\011\003NHAM";
    my $DB1_OLDEST_TOKEN_AGE_MAGIC_TOKEN	= "\015\001\007\011\003OLDESTAGE";
    my $DB1_LAST_EXPIRE_MAGIC_TOKEN		= "\015\001\007\011\003LASTEXPIRE";
    my $DB1_NTOKENS_MAGIC_TOKEN			= "\015\001\007\011\003NTOKENS";
    my $DB1_SCANCOUNT_BASE_MAGIC_TOKEN		= "\015\001\007\011\003SCANBASE";

    @values = (
      $self->{db_toks}->{$DB1_SCANCOUNT_BASE_MAGIC_TOKEN},
      $self->{db_toks}->{$DB1_NSPAM_MAGIC_TOKEN},
      $self->{db_toks}->{$DB1_NHAM_MAGIC_TOKEN},
      $self->{db_toks}->{$DB1_NTOKENS_MAGIC_TOKEN},
      $self->{db_toks}->{$DB1_LAST_EXPIRE_MAGIC_TOKEN},
      $self->{db_toks}->{$DB1_OLDEST_TOKEN_AGE_MAGIC_TOKEN},
      1,
      0,
      0,
      0,
      0,
    );
  }

  foreach (@values) {
    if (!$_ || $_ =~ /\D/) {
      $_ = 0;
    }
  }

  return @values;
}

sub dump_db_toks {
  my ($self, $template, $regex, @vars) = @_;

  while (my ($tok, $tokvalue) = each %{$self->{db_toks}}) {
    next if ($tok =~ MAGIC_RE); # skip magic tokens
    next if (defined $regex && ($tok !~ /$regex/o));

    # We have the value already, so just unpack it.
    my ($ts, $th, $atime) = $self->tok_unpack ($tokvalue);
    
    my $prob = $self->{bayes}->_compute_prob_for_token($tok, $vars[1], $vars[2], $ts, $th);
    $prob ||= 0.5;
    
    my $encoded_tok = unpack("H*",$tok);
    printf $template,$prob,$ts,$th,$atime,$encoded_tok;
  }
}

sub set_last_expire {
  my ($self, $time) = @_;
  $self->{db_toks}->{$LAST_EXPIRE_MAGIC_TOKEN} = time();
}

## Don't bother using get_magic_tokens here.  This token should only
## ever exist when we're running expire, so we don't want to convert it if
## it's there and we're not expiring ...
sub get_running_expire_tok {
  my ($self) = @_;
  my $running = $self->{db_toks}->{$RUNNING_EXPIRE_MAGIC_TOKEN};
  if (!$running || $running =~ /\D/) { return; }
  return $running;
}

sub set_running_expire_tok {
  my ($self) = @_;

  # update the lock and running expire magic token
  $self->{bayes}->{main}->{locker}->refresh_lock ($self->{locked_file});
  $self->{db_toks}->{$RUNNING_EXPIRE_MAGIC_TOKEN} = time();
}

sub remove_running_expire_tok {
  my ($self) = @_;
  delete $self->{db_toks}->{$RUNNING_EXPIRE_MAGIC_TOKEN};
}

###########################################################################

# db abstraction: allow deferred writes, since we will be frequently
# writing while checking.

sub tok_count_change {
  my ($self, $ds, $dh, $tok, $atime) = @_;

  $atime = 0 unless defined $atime;

  if ($self->{bayes}->{main}->{learn_to_journal}) {
    # we can't store the SHA1 binary value in the journal, so convert it
    # to a printable value that can be converted back later
    my $encoded_tok = unpack("H*",$tok);
    $self->defer_update ("c $ds $dh $atime $encoded_tok");
  } else {
    $self->tok_sync_counters ($ds, $dh, $atime, $tok);
  }
}

sub multi_tok_count_change {
  my ($self, $ds, $dh, $tokens, $atime) = @_;

  $atime = 0 unless defined $atime;

  foreach my $tok (keys %{$tokens}) {
    if ($self->{bayes}->{main}->{learn_to_journal}) {
      # we can't store the SHA1 binary value in the journal, so convert it
      # to a printable value that can be converted back later
      my $encoded_tok = unpack("H*",$tok);
      $self->defer_update ("c $ds $dh $atime $encoded_tok");
    } else {
      $self->tok_sync_counters ($ds, $dh, $atime, $tok);
    }
  }
}

sub nspam_nham_get {
  my ($self) = @_;
  my @vars = $self->get_storage_variables();
  ($vars[1], $vars[2]);
}

sub nspam_nham_change {
  my ($self, $ds, $dh) = @_;

  if ($self->{bayes}->{main}->{learn_to_journal}) {
    $self->defer_update ("n $ds $dh");
  } else {
    $self->tok_sync_nspam_nham ($ds, $dh);
  }
}

sub tok_touch {
  my ($self, $tok, $atime) = @_;
  # we can't store the SHA1 binary value in the journal, so convert it
  # to a printable value that can be converted back later
  my $encoded_tok = unpack("H*", $tok);
  $self->defer_update ("t $atime $encoded_tok");
}

sub tok_touch_all {
  my ($self, $tokens, $atime) = @_;

  foreach my $token (@{$tokens}) {
    # we can't store the SHA1 binary value in the journal, so convert it
    # to a printable value that can be converted back later
    my $encoded_tok = unpack("H*", $token);
    $self->defer_update ("t $atime $encoded_tok");
  }
}

sub defer_update {
  my ($self, $str) = @_;
  $self->{string_to_journal} .= "$str\n";
}

###########################################################################

sub cleanup {
  my ($self) = @_;

  my $nbytes = length ($self->{string_to_journal});
  return if ($nbytes == 0);

  my $path = $self->_get_journal_filename();

  # use append mode, write atomically, then close, so simultaneous updates are
  # not lost
  my $conf = $self->{bayes}->{main}->{conf};

  # set the umask to the inverse of what we want ...
  my $umask = umask(0777 - (oct ($conf->{bayes_file_mode}) & 0666));

  if (!open (OUT, ">>".$path)) {
    warn "bayes: cannot write to $path, bayes db update ignored: $!\n";
    umask $umask; # reset umask
    return;
  }
  umask $umask; # reset umask

  # do not use print() here, it will break up the buffer if it's >8192 bytes,
  # which could result in two sets of tokens getting mixed up and their
  # touches missed.
  my $write_failure = 0;
  my $original_point = tell OUT;
  $original_point >= 0  or die "Can't obtain file position: $!";
  my $len;
  do {
    $len = syswrite (OUT, $self->{string_to_journal}, $nbytes);

    # argh, write failure, give up
    if (!defined $len || $len < 0) {
      my $err = '';
      if (!defined $len) {
	$len = 0;
	$err = "  ($!)";
      }
      warn "bayes: write failed to Bayes journal $path ($len of $nbytes)!$err\n";
      last;
    }

    # This shouldn't happen, but could if the fs is full...
    if ($len != $nbytes) {
      warn "bayes: partial write to bayes journal $path ($len of $nbytes), recovering\n";

      # we want to be atomic, so revert the journal file back to where
      # we know it's "good".  if we can't truncate the journal, or we've
      # tried 5 times to do the write, abort!
      if (!truncate(OUT, $original_point) || ($write_failure++ > 4)) {
        warn "bayes: cannot write to bayes journal $path, aborting!\n";
	last;
      }

      # if the fs is full, let's give the system a break
      sleep 1;
    }
  } while ($len != $nbytes);

  if (!close OUT) {
    warn "bayes: cannot write to $path, bayes db update ignored\n";
  }

  $self->{string_to_journal} = '';
}

# Return a qr'd RE to match a token with the correct format's magic token
sub get_magic_re {
  my ($self) = @_;

  if (!defined $self->{db_version} || $self->{db_version} >= 1) {
    return MAGIC_RE;
  }

  # When in doubt, assume v0
  return qr/^\*\*[A-Z]+$/;
}

# provide a more generalized public interface into the journal sync

sub sync {
  my ($self, $opts) = @_;

  return $self->_sync_journal($opts);
}

###########################################################################
# And this method reads the journal and applies the changes in one
# (locked) transaction.

sub _sync_journal {
  my ($self, $opts) = @_;
  my $ret = 0;

  my $path = $self->_get_journal_filename();

  # if $path doesn't exist, or it's not a file, or is 0 bytes in length, return
  if (!stat($path) || !-f _ || -z _) {
    return 0;
  }

  my $eval_stat;
  eval {
    local $SIG{'__DIE__'};	# do not run user die() traps in here
    if ($self->tie_db_writable()) {
      $ret = $self->_sync_journal_trapped($opts, $path);
    }
    1;
  } or do {
    $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
  };

  # ok, untie from write-mode if we can
  if (!$self->{bayes}->{main}->{learn_caller_will_untie}) {
    $self->untie_db();
  }

  # handle any errors that may have occurred
  if (defined $eval_stat) {
    warn "bayes: $eval_stat\n";
    return 0;
  }

  $ret;
}

sub _sync_journal_trapped {
  my ($self, $opts, $path) = @_;

  # Flag that we're doing work
  $self->set_running_expire_tok();

  my $started = time();
  my $count = 0;
  my $total_count = 0;
  my %tokens;
  my $showdots = $opts->{showdots};
  my $retirepath = $path.".old";

  # if $path doesn't exist, or it's not a file, or is 0 bytes in length,
  # return we have to check again since the file may have been removed
  # by a recent bayes db upgrade ...
  if (!stat($path) || !-f _ || -z _) {
    return 0;
  }

  if (!-r $path) { # will we be able to read the file?
    warn "bayes: bad permissions on journal, can't read: $path\n";
    return 0;
  }

  # This is the critical phase (moving files around), so don't allow
  # it to be interrupted.
  {
    local $SIG{'INT'} = 'IGNORE';
    local $SIG{'TERM'} = 'IGNORE';
    local $SIG{'HUP'} = 'IGNORE' if !am_running_on_windows();

    # retire the journal, so we can update the db files from it in peace.
    # TODO: use locking here
    if (!rename ($path, $retirepath)) {
      warn "bayes: failed rename $path to $retirepath\n";
      return 0;
    }

    # now read the retired journal
    local *JOURNAL;
    if (!open (JOURNAL, "<$retirepath")) {
      warn "bayes: cannot open read $retirepath\n";
      return 0;
    }


    # Read the journal
    for ($!=0; defined($_=<JOURNAL>); $!=0) {
      $total_count++;

      if (/^t (\d+) (.+)$/) { # Token timestamp update, cache resultant entries
	my $tok = pack("H*",$2);
	$tokens{$tok} = $1+0 if (!exists $tokens{$tok} || $1+0 > $tokens{$tok});
      } elsif (/^c (-?\d+) (-?\d+) (\d+) (.+)$/) { # Add/full token update
	my $tok = pack("H*",$4);
	$self->tok_sync_counters ($1+0, $2+0, $3+0, $tok);
	$count++;
      } elsif (/^n (-?\d+) (-?\d+)$/) { # update ham/spam count
	$self->tok_sync_nspam_nham ($1+0, $2+0);
	$count++;
      } elsif (/^m ([hsf]) (.+)$/) { # update msgid seen database
	if ($1 eq "f") {
	  $self->_seen_delete_direct($2);
	}
	else {
	  $self->_seen_put_direct($2,$1);
	}
	$count++;
      } else {
	warn "bayes: gibberish entry found in journal: $_";
      }
    }
    defined $_ || $!==0  or
      $!==EBADF ? dbg("bayes: error reading journal file: $!")
                : die "error reading journal file: $!";
    close(JOURNAL) or die "Can't close journal file: $!";

    # Now that we've determined what tokens we need to update and their
    # final values, update the DB.  Should be much smaller than the full
    # journal entries.
    while (my ($k,$v) = each %tokens) {
      $self->tok_touch_token ($v, $k);

      if ((++$count % 1000) == 0) {
	if ($showdots) { print STDERR "."; }
	$self->set_running_expire_tok();
      }
    }

    if ($showdots) { print STDERR "\n"; }

    # we're all done, so unlink the old journal file
    unlink ($retirepath) || warn "bayes: can't unlink $retirepath: $!\n";

    $self->{db_toks}->{$LAST_JOURNAL_SYNC_MAGIC_TOKEN} = $started;

    my $done = time();
    my $msg = ("bayes: synced databases from journal in " .
	       ($done - $started) .
	       " seconds: $count unique entries ($total_count total entries)");

    if ($opts->{verbose}) {
      print $msg,"\n";
    } else {
      dbg($msg);
    }
  }

  # else, that's the lot, we're synced.  return
  return 1;
}

sub tok_touch_token {
  my ($self, $atime, $tok) = @_;
  my ($ts, $th, $oldatime) = $self->tok_get ($tok);

  # If the new atime is < the old atime, ignore the update
  # We figure that we'll never want to lower a token atime, so abort if
  # we try.  (journal out of sync, etc.)
  return if ($oldatime >= $atime);

  $self->tok_put ($tok, $ts, $th, $atime);
}

sub tok_sync_counters {
  my ($self, $ds, $dh, $atime, $tok) = @_;
  my ($ts, $th, $oldatime) = $self->tok_get ($tok);
  $ts += $ds; if ($ts < 0) { $ts = 0; }
  $th += $dh; if ($th < 0) { $th = 0; }

  # Don't roll the atime of tokens backwards ...
  $atime = $oldatime if ($oldatime > $atime);

  $self->tok_put ($tok, $ts, $th, $atime);
}

sub tok_put {
  my ($self, $tok, $ts, $th, $atime) = @_;
  $ts ||= 0;
  $th ||= 0;

  # Ignore magic tokens, the don't go in this way ...
  return if ($tok =~ MAGIC_RE);

  # use defined() rather than exists(); the latter is not supported
  # by NDBM_File, believe it or not.  Using defined() did not
  # indicate any noticeable speed hit in my testing. (Mar 31 2003 jm)
  my $exists_already = defined $self->{db_toks}->{$tok};

  if ($ts == 0 && $th == 0) {
    return if (!$exists_already); # If the token doesn't exist, just return
    $self->{db_toks}->{$NTOKENS_MAGIC_TOKEN}--;
    delete $self->{db_toks}->{$tok};
  } else {
    if (!$exists_already) { # If the token doesn't exist, raise the token count
      $self->{db_toks}->{$NTOKENS_MAGIC_TOKEN}++;
    }

    $self->{db_toks}->{$tok} = $self->tok_pack ($ts, $th, $atime);

    my $newmagic = $self->{db_toks}->{$NEWEST_TOKEN_AGE_MAGIC_TOKEN};
    if (!defined ($newmagic) || $atime > $newmagic) {
      $self->{db_toks}->{$NEWEST_TOKEN_AGE_MAGIC_TOKEN} = $atime;
    }

    # Make sure to check for either !defined or "" ...  Apparently
    # sometimes the DB module doesn't return the value correctly. :(
    my $oldmagic = $self->{db_toks}->{$OLDEST_TOKEN_AGE_MAGIC_TOKEN};
    if (!defined ($oldmagic) || $oldmagic eq "" || $atime < $oldmagic) {
      $self->{db_toks}->{$OLDEST_TOKEN_AGE_MAGIC_TOKEN} = $atime;
    }
  }
}

sub tok_sync_nspam_nham {
  my ($self, $ds, $dh) = @_;
  my ($ns, $nh) = ($self->get_storage_variables())[1,2];
  if ($ds) { $ns += $ds; } if ($ns < 0) { $ns = 0; }
  if ($dh) { $nh += $dh; } if ($nh < 0) { $nh = 0; }
  $self->{db_toks}->{$NSPAM_MAGIC_TOKEN} = $ns;
  $self->{db_toks}->{$NHAM_MAGIC_TOKEN} = $nh;
}

###########################################################################

sub _get_journal_filename {
  my ($self) = @_;

  my $main = $self->{bayes}->{main};
  return $main->sed_path($main->{conf}->{bayes_path}."_journal");
}

###########################################################################

# this is called directly from sa-learn(1).
sub perform_upgrade {
  my ($self, $opts) = @_;
  my $ret = 0;

  my $eval_stat;
  eval {
    local $SIG{'__DIE__'};	# do not run user die() traps in here

    use File::Basename;

    # bayes directory
    my $main = $self->{bayes}->{main};
    my $path = $main->sed_path($main->{conf}->{bayes_path});

    # prevent dirname() from tainting the result, it assumes $1 is not tainted
    local($1,$2,$3);  # Bug 6310;  perl #67962 (fixed in perl 5.12/5.13)
    my $dir = dirname($path);

    # make temporary copy since old dbm and new dbm may have same name
    opendir(DIR, $dir) or die "bayes: can't opendir $dir: $!";
    my @files = grep { /^bayes_(?:seen|toks)(?:\.\w+)?$/ } readdir(DIR);
    closedir(DIR) or die "bayes: can't close directory $dir: $!";
    if (@files < 2 || !grep(/bayes_seen/,@files) || !grep(/bayes_toks/,@files))
    {
      die "bayes: unable to find bayes_toks and bayes_seen, stopping\n";
    }
    # untaint @files (already safe after grep)
    untaint_var(\@files);
 	 
    for (@files) {
      my $src = "$dir/$_";
      my $dst = "$dir/old_$_";
      eval q{
        use File::Copy;
        copy($src, $dst);
      } || die "bayes: can't copy $src to $dst: $!\n";
    }

    # delete previous to make way for import
    for (@files) { unlink("$dir/$_"); }

    # import
    if ($self->tie_db_writable()) {
      $ret += $self->upgrade_old_dbm_files_trapped("$dir/old_bayes_seen",
						   $self->{db_seen});
      $ret += $self->upgrade_old_dbm_files_trapped("$dir/old_bayes_toks",
						   $self->{db_toks});
    }

    if ($ret == 2) {
      print "import successful, original files saved with \"old\" prefix\n";
    }
    else {
      print "import failed, original files saved with \"old\" prefix\n";
    }
    1;
  } or do {
    $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
  };

  $self->untie_db();

  # if we died, untie the dbm files
  if (defined $eval_stat) {
    warn "bayes: perform_upgrade: $eval_stat\n";
    return 0;
  }
  $ret;
}

sub upgrade_old_dbm_files_trapped {
  my ($self, $filename, $output) = @_;

  my $count;
  my %in;

  print "upgrading to DB_File, please be patient: $filename\n";

  # try each type of file until we find one with > 0 entries
  for my $dbm ('DB_File', 'GDBM_File', 'NDBM_File', 'SDBM_File') {
    $count = 0;
    # wrap in eval so it doesn't run in general use.  This accesses db
    # modules directly.
    # Note: (bug 2390), the 'use' needs to be on the same line as the eval
    # for RPM dependency checks to work properly.  It's lame, but...
    my $eval_stat;
    eval 'use ' . $dbm . ';
      tie %in, "' . $dbm . '", $filename, O_RDONLY, 0600;
      %{ $output } = %in;
      $count = scalar keys %{ $output };
      untie %in;
      1;
    ' or do {
      $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
    };
    if (defined $eval_stat) {
      print "$dbm: $dbm module not installed(?), nothing copied: $eval_stat\n";
      dbg("bayes: error was: $eval_stat");
    }
    elsif ($count == 0) {
      print "$dbm: no database of that kind found, nothing copied\n";
    }
    else {
      print "$dbm: copied $count entries\n";
      return 1;
    }
  }

  return 0;
}

sub clear_database {
  my ($self) = @_;

  return 0 unless ($self->tie_db_writable());

  dbg("bayes: untie-ing in preparation for removal.");

  foreach my $dbname (@DBNAMES) {
    my $db_var = 'db_'.$dbname;

    if (exists $self->{$db_var}) {
      # dbg("bayes: untie-ing $db_var");
      untie %{$self->{$db_var}};
      delete $self->{$db_var};
    }
  }

  my $path = $self->{bayes}->{main}->sed_path($self->{bayes}->{main}->{conf}->{bayes_path});

  foreach my $dbname (@DBNAMES, 'journal') {
    foreach my $ext ($self->DB_EXTENSIONS) {
      my $name = $path.'_'.$dbname.$ext;
      my $ret = unlink $name;
      dbg("bayes: clear_database: %s %s",
          $ret ? 'removed' : 'tried to remove', $name);
    }
  }

  # the journal file needs to be done separately since it has no extension
  foreach my $dbname ('journal') {
    my $name = $path.'_'.$dbname;
    my $ret = unlink $name;
    dbg("bayes: clear_database: %s %s",
        $ret ? 'removed' : 'tried to remove', $name);
  }

  $self->untie_db();

  return 1;
}

sub backup_database {
  my ($self) = @_;

  # we tie writable because we want the upgrade code to kick in if needed
  return 0 unless ($self->tie_db_writable());

  my @vars = $self->get_storage_variables();

  print "v\t$vars[6]\tdb_version # this must be the first line!!!\n";
  print "v\t$vars[1]\tnum_spam\n";
  print "v\t$vars[2]\tnum_nonspam\n";

  while (my ($tok, $packed) = each %{$self->{db_toks}}) {
    next if ($tok =~ MAGIC_RE); # skip magic tokens

    my ($ts, $th, $atime) = $self->tok_unpack($packed);
    my $encoded_token = unpack("H*",$tok);
    print "t\t$ts\t$th\t$atime\t$encoded_token\n";
  }

  while (my ($msgid, $flag) = each %{$self->{db_seen}}) {
    print "s\t$flag\t$msgid\n";
  }

  $self->untie_db();

  return 1;
}

sub restore_database {
  my ($self, $filename, $showdots) = @_;

  local *DUMPFILE;
  if (!open(DUMPFILE, '<', $filename)) {
    dbg("bayes: unable to open backup file $filename: $!");
    return 0;
  }
   
  if (!$self->tie_db_writable()) {
    dbg("bayes: failed to tie db writable");
    return 0;
  }

  my $main = $self->{bayes}->{main};
  my $path = $main->sed_path($main->{conf}->{bayes_path});

  # use a temporary PID-based suffix just in case another one was
  # created previously by an interrupted expire
  my $tmpsuffix = "convert$$";
  my $tmptoksdbname = $path.'_toks.'.$tmpsuffix;
  my $tmpseendbname = $path.'_seen.'.$tmpsuffix;
  my $toksdbname = $path.'_toks';
  my $seendbname = $path.'_seen';

  my %new_toks;
  my %new_seen;
  my $umask = umask 0;
  unless (tie %new_toks, $self->DBM_MODULE, $tmptoksdbname, O_RDWR|O_CREAT|O_EXCL,
	  (oct ($main->{conf}->{bayes_file_mode}) & 0666)) {
    dbg("bayes: failed to tie temp toks db: $!");
    $self->untie_db();
    umask $umask;
    return 0;
  }
  unless (tie %new_seen, $self->DBM_MODULE, $tmpseendbname, O_RDWR|O_CREAT|O_EXCL,
	  (oct ($main->{conf}->{bayes_file_mode}) & 0666)) {
    dbg("bayes: failed to tie temp seen db: $!");
    untie %new_toks;
    $self->_unlink_file($tmptoksdbname);
    $self->untie_db();
    umask $umask;
    return 0;
  }
  umask $umask;

  my $line_count = 0;
  my $db_version;
  my $token_count = 0;
  my $num_spam;
  my $num_ham;
  my $error_p = 0;
  my $newest_token_age = 0;
  # Kinda wierd I know, but we need a nice big value and we know there will be
  # no tokens > time() since we reset atime if > time(), so use that with a
  # little buffer just in case.
  my $oldest_token_age = time() + 100000;

  my $line = <DUMPFILE>;
  defined $line  or die "Error reading dump file: $!";
  $line_count++;

  # We require the database version line to be the first in the file so we can
  # figure out how to properly deal with the file.  If it is not the first
  # line then fail
  if ($line =~ m/^v\s+(\d+)\s+db_version/) {
    $db_version = $1;
  }
  else {
    dbg("bayes: database version must be the first line in the backup file, correct and re-run");
    untie %new_toks;
    untie %new_seen;
    $self->_unlink_file($tmptoksdbname);
    $self->_unlink_file($tmpseendbname);
    $self->untie_db();
    return 0;
  }

  unless ($db_version == 2 || $db_version == 3) {
    warn("bayes: database version $db_version is unsupported, must be version 2 or 3");
    untie %new_toks;
    untie %new_seen;
    $self->_unlink_file($tmptoksdbname);
    $self->_unlink_file($tmpseendbname);
    $self->untie_db();
    return 0;
  }

  for ($!=0; defined($line=<DUMPFILE>); $!=0) {
    chomp($line);
    $line_count++;

    if ($line_count % 1000 == 0) {
      print STDERR "." if ($showdots);
    }

    if ($line =~ /^v\s+/) { # variable line
      my @parsed_line = split(/\s+/, $line, 3);
      my $value = $parsed_line[1] + 0;
      if ($parsed_line[2] eq 'num_spam') {
	$num_spam = $value;
      }
      elsif ($parsed_line[2] eq 'num_nonspam') {
	$num_ham = $value;
      }
      else {
	dbg("bayes: restore_database: skipping unknown line: $line");
      }
    }
    elsif ($line =~ /^t\s+/) { # token line
      my @parsed_line = split(/\s+/, $line, 5);
      my $spam_count = $parsed_line[1] + 0;
      my $ham_count = $parsed_line[2] + 0;
      my $atime = $parsed_line[3] + 0;
      my $token = $parsed_line[4];

      my $token_warn_p = 0;
      my @warnings;

      if ($spam_count < 0) {
	$spam_count = 0;
	push(@warnings, 'spam count < 0, resetting');
	$token_warn_p = 1;
      }
      if ($ham_count < 0) {
	$ham_count = 0;
	push(@warnings, 'ham count < 0, resetting');
	$token_warn_p = 1;
      }

      if ($spam_count == 0 && $ham_count == 0) {
	dbg("bayes: token has zero spam and ham count, skipping");
	next;
      }

      if ($atime > time()) {
	$atime = time();
	push(@warnings, 'atime > current time, resetting');
	$token_warn_p = 1;
      }

      if ($token_warn_p) {
	dbg("bayes: token (%s) has the following warnings:\n%s",
            $token, join("\n",@warnings));
      }

      # database versions < 3 did not encode their token values
      if ($db_version < 3) {
	$token = substr(sha1($token), -5);
      }
      else {
	# turn unpacked binary token back into binary value
	$token = pack("H*",$token);
      }

      $new_toks{$token} = $self->tok_pack($spam_count, $ham_count, $atime);
      if ($atime < $oldest_token_age) {
	$oldest_token_age = $atime;
      }
      if ($atime > $newest_token_age) {
	$newest_token_age = $atime;
      }
      $token_count++;
    }
    elsif ($line =~ /^s\s+/) { # seen line
      my @parsed_line = split(/\s+/, $line, 3);
      my $flag = $parsed_line[1];
      my $msgid = $parsed_line[2];

      unless ($flag eq 'h' || $flag eq 's') {
	dbg("bayes: unknown seen flag ($flag) for line: $line, skipping");
	next;
      }

      unless ($msgid) {
	dbg("bayes: blank msgid for line: $line, skipping");
	next;
      }

      $new_seen{$msgid} = $flag;
    }
    else {
      dbg("bayes: skipping unknown line: $line");
      next;
    }
  }
  defined $line || $!==0  or die "Error reading dump file: $!";
  close(DUMPFILE) or die "Can't close dump file: $!";

  print STDERR "\n" if ($showdots);

  unless (defined($num_spam)) {
    dbg("bayes: unable to find num spam, please check file");
    $error_p = 1;
  }

  unless (defined($num_ham)) {
    dbg("bayes: unable to find num ham, please check file");
    $error_p = 1;
  }

  if ($error_p) {
    dbg("bayes: error(s) while attempting to load $filename, correct and re-run");

    untie %new_toks;
    untie %new_seen;
    $self->_unlink_file($tmptoksdbname);
    $self->_unlink_file($tmpseendbname);
    $self->untie_db();
    return 0;
  }

  # set the calculated magic tokens
  $new_toks{$DB_VERSION_MAGIC_TOKEN} = $self->DB_VERSION();
  $new_toks{$NTOKENS_MAGIC_TOKEN} = $token_count;
  $new_toks{$NSPAM_MAGIC_TOKEN} = $num_spam;
  $new_toks{$NHAM_MAGIC_TOKEN} = $num_ham;
  $new_toks{$NEWEST_TOKEN_AGE_MAGIC_TOKEN} = $newest_token_age;
  $new_toks{$OLDEST_TOKEN_AGE_MAGIC_TOKEN} = $oldest_token_age;

  # go ahead and zero out these, chances are good that they are bogus anyway.
  $new_toks{$LAST_EXPIRE_MAGIC_TOKEN} = 0;
  $new_toks{$LAST_JOURNAL_SYNC_MAGIC_TOKEN} = 0;
  $new_toks{$LAST_ATIME_DELTA_MAGIC_TOKEN} = 0;
  $new_toks{$LAST_EXPIRE_REDUCE_MAGIC_TOKEN} = 0;

  local $SIG{'INT'} = 'IGNORE';
  local $SIG{'TERM'} = 'IGNORE';
  local $SIG{'HUP'} = 'IGNORE' if !am_running_on_windows();

  untie %new_toks;
  untie %new_seen;
  $self->untie_db();

  # Here is where something can go horribly wrong and screw up the bayes
  # database files.  If we are able to copy one and not the other then it
  # will leave the database in an inconsistent state.  Since this is an
  # edge case, and they're trying to replace the DB anyway we should be ok.
  unless ($self->_rename_file($tmptoksdbname, $toksdbname)) {
    dbg("bayes: error while renaming $tmptoksdbname to $toksdbname: $!");
    return 0;
  }
  unless ($self->_rename_file($tmpseendbname, $seendbname)) {
    dbg("bayes: error while renaming $tmpseendbname to $seendbname: $!");
    dbg("bayes: database now in inconsistent state");
    return 0;
  }

  dbg("bayes: parsed $line_count lines");
  dbg("bayes: created database with $token_count tokens based on $num_spam spam messages and $num_ham ham messages");

  return 1;
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
  my ($self, $value) = @_;
  $value ||= 0;

  my ($packed, $atime);
  if ($self->{db_version} >= 1) {
    ($packed, $atime) = unpack("CV", $value);
  }
  elsif ($self->{db_version} == 0) {
    ($packed, $atime) = unpack("CS", $value);
  }

  if (($packed & FORMAT_FLAG) == ONE_BYTE_FORMAT) {
    return (($packed & ONE_BYTE_SSS_BITS) >> 3,
		$packed & ONE_BYTE_HHH_BITS,
		$atime || 0);
  }
  elsif (($packed & FORMAT_FLAG) == TWO_LONGS_FORMAT) {
    my ($packed, $ts, $th, $atime);
    if ($self->{db_version} >= 1) {
      ($packed, $ts, $th, $atime) = unpack("CVVV", $value);
    }
    elsif ($self->{db_version} == 0) {
      ($packed, $ts, $th, $atime) = unpack("CLLS", $value);
    }
    return ($ts || 0, $th || 0, $atime || 0);
  }
  # other formats would go here...
  else {
    warn "bayes: unknown packing format for bayes db, please re-learn: $packed";
    return (0, 0, 0);
  }
}

sub tok_pack {
  my ($self, $ts, $th, $atime) = @_;
  $ts ||= 0; $th ||= 0; $atime ||= 0;
  if ($ts < 8 && $th < 8) {
    return pack ("CV", ONE_BYTE_FORMAT | ($ts << 3) | $th, $atime);
  } else {
    return pack ("CVVV", TWO_LONGS_FORMAT, $ts, $th, $atime);
  }
}

###########################################################################

sub db_readable {
  my ($self) = @_;
  return $self->{already_tied};
}

sub db_writable {
  my ($self) = @_;
  return $self->{already_tied} && $self->{is_locked};
}

###########################################################################

sub _unlink_file {
  my ($self, $filename) = @_;

  unlink $filename;
}

sub _rename_file {
  my ($self, $sourcefilename, $targetfilename) = @_;

  return 0 unless (rename($sourcefilename, $targetfilename));

  return 1;
}

sub sa_die { Mail::SpamAssassin::sa_die(@_); }

1;
