# <@LICENSE>
# ====================================================================
# The Apache Software License, Version 1.1
# 
# Copyright (c) 2000 The Apache Software Foundation.  All rights
# reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
# 
# 3. The end-user documentation included with the redistribution,
#    if any, must include the following acknowledgment:
#       "This product includes software developed by the
#        Apache Software Foundation (http://www.apache.org/)."
#    Alternately, this acknowledgment may appear in the software itself,
#    if and wherever such third-party acknowledgments normally appear.
# 
# 4. The names "Apache" and "Apache Software Foundation" must
#    not be used to endorse or promote products derived from this
#    software without prior written permission. For written
#    permission, please contact apache@apache.org.
# 
# 5. Products derived from this software may not be called "Apache",
#    nor may "Apache" appear in their name, without prior written
#    permission of the Apache Software Foundation.
# 
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
# ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
# USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
# OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
# ====================================================================
# 
# This software consists of voluntary contributions made by many
# individuals on behalf of the Apache Software Foundation.  For more
# information on the Apache Software Foundation, please see
# <http://www.apache.org/>.
# 
# Portions of this software are based upon public domain software
# originally written at the National Center for Supercomputing Applications,
# University of Illinois, Urbana-Champaign.
# </@LICENSE>

package Mail::SpamAssassin::UnixLocker;

use strict;
use bytes;

use Mail::SpamAssassin;
use Mail::SpamAssassin::Locker;
use Mail::SpamAssassin::Util;
use File::Spec;
use Time::Local;

use vars qw{
  @ISA
};

@ISA = qw(Mail::SpamAssassin::Locker);

###########################################################################

sub new {
  my $class = shift;
  my $self = $class->SUPER::new(@_);
  $self;
}

###########################################################################
# NFS-safe locking (I hope!):
# Attempt to create a file lock, using NFS-safe locking techniques.
#
# Locking code adapted from code by Alexis Rosen <alexis@panix.com>
# by Kelsey Cummings <kgc@sonic.net>, with mods by jm and quinlan

use constant LOCK_MAX_AGE => 600;	# seconds 

sub safe_lock {
  my ($self, $path, $max_retries) = @_;
  my $is_locked = 0;
  my @stat;

  $max_retries ||= 30;

  my $hname = Mail::SpamAssassin::Util::fq_hostname();
  my $lock_file = "$path.lock";
  my $lock_tmp = Mail::SpamAssassin::Util::untaint_file_path
					("$path.lock.$hname.$$");

  my $umask = 077;
  if (!open(LTMP, ">$lock_tmp")) {
      umask $umask;
      die "lock: $$ cannot create tmp lockfile $lock_tmp for $lock_file: $!\n";
  }
  umask $umask;
  autoflush LTMP 1;
  dbg("lock: $$ created $lock_tmp");

  for (my $retries = 0; $retries < $max_retries; $retries++) {
    if ($retries > 0) {
      select(undef, undef, undef, (rand(1.0) + 0.5));
    }
    print LTMP "$hname.$$\n";
    dbg("lock: $$ trying to get lock on $path with $retries retries");
    if (link($lock_tmp, $lock_file)) {
      dbg("lock: $$ link to $lock_file: link ok");
      $is_locked = 1;
      last;
    }
    # link _may_ return false even if the link _is_ created
    @stat = stat($lock_tmp);
    if ($stat[3] > 1) {
      dbg("lock: $$ link to $lock_file: stat ok");
      $is_locked = 1;
      last;
    }
    # check age of lockfile ctime
    my $now = ($#stat < 11 ? undef : $stat[10]);
    @stat = stat($lock_file);
    my $lock_age = ($#stat < 11 ? undef : $stat[10]);
    if (!defined($lock_age) || ($now - $lock_age) > LOCK_MAX_AGE) {
      # we got a stale lock, break it
      dbg("lock: $$ breaking stale $lock_file: age=" .
	  (defined $lock_age ? $lock_age : "undef") . " now=$now");
      unlink ($lock_file) || warn "lock: $$ unlink of lock file $lock_file failed: $!\n";
    }
  }

  close(LTMP);
  unlink ($lock_tmp) || warn "lock: $$ unlink of temp lock $lock_tmp failed: $!\n";

  return $is_locked;
}

###########################################################################

sub safe_unlock {
  my ($self, $path) = @_;

  unlink ("$path.lock") || warn "unlock: $$ unlink failed: $path.lock\n";
  dbg("unlock: $$ unlink $path.lock");
}

###########################################################################

sub dbg { Mail::SpamAssassin::dbg (@_); }

1;
