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

Mail::SpamAssassin::Plugin::AccessDB - check message against Access Database

=head1 SYNOPSIS

  loadplugin     Mail::SpamAssassin::Plugin::AccessDB

  header   ACCESSDB  eval:check_access_database('/etc/mail/access.db')
  describe ACCESSDB  Message would have been caught by accessdb
  tflags   ACCESSDB  userconf
  score    ACCESSDB  2

=head1 DESCRIPTION

Many MTAs support access databases, such as Sendmail, Postfix, etc.
This plugin does similar checks to see whether a message would have
been flagged.

The rule returns false if an entry isn't found, or the entry has a RHS of
I<OK> or I<SKIP>.

The rule returns true if an entry exists and has a RHS of I<REJECT>, I<ERROR>,
or I<DISCARD>.

Note: only the first word (split on non-word characters) of the RHS
is checked, so C<error:5.7.1:...> means C<ERROR>.

B<AccessDB Pointers:>

  http://www.faqs.org/docs/securing/chap22sec178.html
  http://www.postfix.org/access.5.html

=cut

package Mail::SpamAssassin::Plugin::AccessDB;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Fcntl;
use strict;
use warnings;
use bytes;
use re 'taint';

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

use constant HAS_DB_FILE => eval { require DB_File; };

sub new {
  my $class = shift;
  my $mailsaobject = shift;

  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->register_eval_rule("check_access_database");

  return $self;
}

sub check_access_database {
  my ($self, $pms, $path) = @_;

  if (!HAS_DB_FILE) {
    return 0;
  }

  my %access;
  my %ok = map { $_ => 1 } qw/ OK SKIP /;
  my %bad = map { $_ => 1 } qw/ REJECT ERROR DISCARD /;

  $path = $self->{main}->sed_path ($path);
  dbg("accessdb: tie-ing to DB file R/O in $path");
  if (tie %access,"DB_File",$path, O_RDONLY) {
    my @lookfor;

    # Look for "From:" versions as well!
    foreach my $from ($pms->all_from_addrs()) {
      # $user."\@"
      # rotate through $domain and check
      my ($user,$domain) = split(/\@/, $from,2);
      push(@lookfor, "From:$from",$from);
      if ($user) {
        push(@lookfor, "From:$user\@", "$user\@");
      }
      if ($domain) {
        while ($domain =~ /\./) {
          push(@lookfor, "From:$domain", $domain);
          $domain =~ s/^[^.]*\.//;
        }
        push(@lookfor, "From:$domain", $domain);
      }
    }

    # we can only match this if we have at least 1 untrusted header
    if ($pms->{num_relays_untrusted} > 0) {
      my $lastunt = $pms->{relays_untrusted}->[0];

      # If there was a reverse lookup, use it in a lookup
      if (! $lastunt->{no_reverse_dns}) {
        my $rdns = $lastunt->{lc_rdns};
        while($rdns =~ /\./) {
          push(@lookfor, "From:$rdns", $rdns);
          $rdns =~ s/^[^.]*\.//;
        }
        push(@lookfor, "From:$rdns", $rdns);
      }

      # do both IP and net (rotate over IP)
      my ($ip) = $lastunt->{ip};
      $ip =~ tr/0-9.//cd;
      while($ip =~ /\./) {
        push(@lookfor, "From:$ip", $ip);
	$ip =~ s/\.[^.]*$//;
      }
      push(@lookfor, "From:$ip", $ip);
    }

    my $retval = 0;
    my %cache;
    foreach (@lookfor) {
      next if ($cache{$_}++);
      dbg("accessdb: looking for $_");

      # Some systems put a null at the end of the key, most don't...
      my $result = $access{$_} || $access{"$_\000"} || next;

      my ($type) = split(/\W/,$result);
      $type = uc $type;

      if (exists $ok{$type}) {
	dbg("accessdb: hit OK: $type, $_");
        $retval = 0;
	last;
      }
      if (exists $bad{$type} || $type =~ /^\d+$/) {
        $retval = 1;
	dbg("accessdb: hit not-OK: $type, $_");
      }
    }

    dbg("accessdb: untie-ing DB file $path");
    untie %access;

    return $retval;
  }
  else {
    dbg("accessdb: cannot open accessdb $path R/O: $!");
  }
  
  return 0;
}

1;
