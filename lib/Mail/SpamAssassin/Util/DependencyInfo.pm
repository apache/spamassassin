# Helper code to debug dependencies and their versions.

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

Mail:SpamAssassin::Util::DependencyInfo - spamassassin debugging helpers

=head1 SYNOPSIS

loadplugin Mail:SpamAssassin::Util::DependencyInfo

=cut

package Mail::SpamAssassin::Util::DependencyInfo;

use strict;
use warnings;
use bytes;
use re 'taint';

use vars qw (
  @MODULES @OPTIONAL_MODULES $EXIT_STATUS $WARNINGS @OPTIONAL_BINARIES @BINARIES
);

my $have_sha  = eval { require Digest::SHA  };
my $have_sha1 = eval { require Digest::SHA1 };

@MODULES = (
$have_sha1 ? {
  'module' => 'Digest::SHA1',
  'version' => 0,
  'desc' => 'The Digest::SHA1 module is used as a cryptographic hash for some
  tests and the Bayes subsystem.  It is also required by the Razor2 plugin.',
} : {
  'module' => 'Digest::SHA',
  'version' => 0,
  'desc' => 'The Digest::SHA module is used as a cryptographic hash for some
  tests and the Bayes subsystem.  It is also required by the DKIM plugin.',
},
{
  'module' => 'HTML::Parser',
  'version' => '3.43',
  'desc' => 'HTML is used for an ever-increasing amount of email so this dependency
  is unavoidable.  Run "perldoc -q html" for additional information.',
},
{
  module => 'Net::DNS',
  version => ($^O =~ /^(mswin|dos|os2)/oi ? '0.46' : '0.34'),
  desc => 'Used for all DNS-based tests (SBL, XBL, SpamCop, DSBL, etc.),
  perform MX checks, and is also used when manually reporting spam to
  SpamCop.

  You need to make sure the Net::DNS version is sufficiently up-to-date:

  - version 0.34 or higher on Unix systems
  - version 0.46 or higher on Windows systems',
},
{
  'module' => 'NetAddr::IP',
  'version' => '4.010',
  'desc' => "Used in determining which DNS tests are to be done for each of
  the header's received fields, used by AWL plugin for extracting network
  address from an IPv6 addresses (and from IPv4 address on nondefault mask),
  and used by DNSxL rules for assembling DNS queries out of IPv6 addresses.
  4.010 fixes an issue where NetAddr::IP::full6() causes a full6.al include
  error.
  Avoid versions 4.034 to 4.035 and 4.045 to 4.054",
},
{
  module => 'Time::HiRes',
  version => 0,
  desc => 'Used by asynchronous DNS lookups to operate timeouts with subsecond
  precision and to report processing times accurately.'
},
{
  module => 'Archive::Tar',
  version => '1.23',
  desc => 'The "sa-update" program requires this module to access tar update
  archive files.',
},
{
  module => 'IO::Zlib',
  version => '1.04',
  desc => 'The "sa-update" program requires this module to access compressed
  update archive files.',
},
);

my @OPTIONAL_MODULES = (
$have_sha ? {
  'module' => 'Digest::SHA1',
  'version' => 0,
  'desc' => 'The Digest::SHA1 module is required by the Razor2 plugin.',
} : {
  'module' => 'Digest::SHA',
  'version' => 0,
  'desc' => 'The Digest::SHA module is required by the DKIM plugin.',
},
{
  module => 'MIME::Base64',
  version => 0,
  desc => 'This module is highly recommended to increase the speed with which
  Base64 encoded messages/mail parts are decoded.',
},
{
  module => 'DB_File',
  version => 0,
  desc => 'Used to store data on-disk, for the Bayes-style logic and
  auto-whitelist.  *Much* more efficient than the other standard Perl
  database packages.  Strongly recommended.',
},
{
  module => 'Net::SMTP',
  alt_name => 'libnet',
  version => 0,
  desc => 'Used when manually reporting spam to SpamCop with "spamassassin -r".',
},
{
  module => 'Mail::SPF',
  version => 0,
  desc => 'Used to check DNS Sender Policy Framework (SPF) records to fight email
  address forgery and make it easier to identify spams.',
},
{
  module => 'Geo::IP',
  version => 0,
  desc => 'Used by the RelayCountry plugin (not enabled by default) to determine
  the domain country codes of each relay in the path of an email.  Also used by 
  the URILocalBL plugin to provide ISP and Country code based filtering.',
},
{
  module => 'Net::CIDR::Lite',
  version => 0,
  desc => 'Used by the URILocalBL plugin to process IP address ranges.',
},
{
  module => 'Razor2::Client::Agent',
  alt_name => 'Razor2',
  version => '2.61',
  desc => 'Used to check message signatures against Vipul\'s Razor collaborative
  filtering network. Razor has a large number of dependencies on CPAN
  modules. Feel free to skip installing it, if this makes you nervous;
  SpamAssassin will still work well without it.

  More info on installing and using Razor can be found
  at http://wiki.apache.org/spamassassin/InstallingRazor .',
},
#{
# module => 'Net::Ident',
# version => 0,
# desc => 'If you plan to use the --auth-ident option to spamd, you will need
# to install this module.',
#},
{
  module => 'IO::Socket::IP',
  version => 0.09,
  desc => 'Installing this module is recommended if spamd is to listen
  on IPv6 sockets or if DNS queries should go to an IPv6 name server.
  If IO::Socket::IP is not available, using an older module
  IO::Socket::INET6 will be attempted, and in its absence the support
  for IPv6 will not be available. Some plugins and underlying
  modules may also prefer IO::Socket::IP over IO::Socket::INET6.',
},
{
  module => 'IO::Socket::INET6',
  version => 0,
  desc => 'This module is an older alternative to IO::Socket::IP.
  Spamd, as well some underlying modules, will fall back to using
  IO::Socket::INET6 if IO::Socket::IP is unavailable. One or the other
  module is required to support IPv6 (e.g. in spamd/spamc protocol,
  for DNS lookups or in plugins like DCC). Some plugins or underlying
  modules may still require IO::Socket::INET6 for IPv6 support even
  if IO::Socket::IP is available.',
},
{
  module => 'IO::Socket::SSL',
  version => 0,
  desc => 'If you wish to use SSL encryption to communicate between spamc and
  spamd (the --ssl option to spamd), you need to install this
  module. (You will need the OpenSSL libraries and use the
  ENABLE_SSL="yes" argument to Makefile.PL to build and run an SSL
  compatibile spamc.)',
},
{
  module => 'Compress::Zlib',
  version => 0,
  desc => 'If you wish to use the optional zlib compression for communication
  between spamc and spamd (the -z option to spamc), you need to install
  this module.',
},
{
  module => 'Mail::DKIM',
  version => '0.31',
  recommended_min_version => '0.37',
  desc => 'If this module is installed and the DKIM plugin is enabled,
  SpamAssassin will perform DKIM signature verification when DKIM-Signature
  header fields are present in the message headers, and check ADSP rules
  (e.g. anti-phishing) when a mail message does not contain a valid author
  domain signature. Version 0.37 or later is needed to fully support ADSP.'
},
{
  module => 'DBI',
  version => 0,
  desc => 'If you intend to use SpamAssassin with an SQL database backend for
  user configuration data, Bayes storage, or other storage, you will need
  to have these installed; both the basic DBI module and the DBD driver for
  your database.',
},
{
  module => 'Getopt::Long',
  version => '2.32',        # min version was included in 5.8.0, which works
  desc => 'The "sa-stats.pl" program included in "tools", used to generate
  summary reports from spamd\'s syslog messages, requires this version
  of Getopt::Long or newer.',
},
{
  module => 'LWP::UserAgent',
  version => 0,
  desc => 'The "sa-update" program requires this module to make HTTP requests.',
},
{
  module => 'HTTP::Date',
  version => 0,
  desc => 'The "sa-update" program requires this module to make HTTP
  If-Modified-Since GET requests.',
},
{
  module => 'Encode::Detect::Detector',
  version => 0,
  desc => 'If you plan to use the normalize_charset config setting to
  decode message parts from their declared character set into Unicode, and
  such decoding fails, the Encode::Detect::Detector module (when available)
  may be consulted to provide an alternative guess on a character set of a
  problematic message part.',
},
{
  module => 'Net::Patricia',
  version => 1.16,
  desc => 'If this module is available, it will be used for IP address lookups
  in tables internal_networks, trusted_networks, and msa_networks. Recommended
  when a number of entries in these tables is large, i.e. in hundreds
  or thousands. However, in case of overlapping (or conflicting) networks
  in these tables, lookup results may differ as Net::Patricia finds a
  tightest-matching entry, while a sequential NetAddr::IP search finds
  a first-matching entry. So when overlapping network ranges are given,
  specifying more specific subnets (longest netmask) first, followed by
  wider subnets ensures predictable results.',
},
{
  module => 'Net::DNS::Nameserver',
  version => 0,
  desc => 'Net::DNS:Nameserver is typically part of Net::DNS.  However, RHEL/
  CentOS systems may install it using separate packages.  Because of this, we
  check for both Net::DNS and Net::DNS::Nameserver.  However, 
  Net::DNS::Nameserver is only used in make test as of June 2014.',
},
);

my @BINARIES = ();

my $lwp_note = "   Sa-update will use curl, wget or fetch to download updates.  
   Because perl module LWP does not support IPv6, sa-update as of
   3.4.0 will use these standard programs to download rule updates
   leaving LWP as a fallback if none of the programs are found.

   *IMPORTANT NOTE*: You only need one of these programs.";

my @OPTIONAL_BINARIES = (
{
  binary => 'gpg',
  version => '0',
  recommended_min_version => '1.0.6',
  version_check_params => '--version',
  version_check_regex => 'gpg \(GnuPG\) ([\d\.]*)',
  desc => 'The "sa-update" program requires this executable to verify  
  encryption signatures.  It is not recommended, but you can use 
  "sa-update" with the --no-gpg to skip the verification. ',
},
{
  binary => 'wget',
  version => '0',
  recommended_min_version => '1.8.2',
  version_check_params => '--version',
  version_check_regex => 'Gnu Wget ([\d\.]*)',
  desc => $lwp_note,
},
{
  binary => 'curl',
  version => '0',
  recommended_min_version => '7.2.14',
  version_check_params => '--version',
  version_check_regex => 'curl ([\d\.]*)',
  desc => $lwp_note,
},
#Fetch is a FreeBSD Product. We do not believe it has any way to check the version from
#the command line.  It has been tested with FreeBSD version 8 through 9.1.
{
  binary => 'fetch',
  version => '0',
  
  desc => $lwp_note,
}
);

###########################################################################

=head1 METHODS

=over 4

=item $f->debug_diagnostics ()

Output some diagnostic information, useful for debugging SpamAssassin
problems.

=back

=cut

sub debug_diagnostics {
  my $out = "diag: perl platform: $] $^O\n";

# # this avoids an unsightly warning due to a shortcoming of Net::Ident;
# # "Net::Ident::_export_hooks() called too early to check prototype at
# # /usr/share/perl5/Net/Ident.pm line 29."   It only needs to be
# # called here.
# eval '
#   sub Net::Ident::_export_hooks;
# ';

  foreach my $moddef (@MODULES, @OPTIONAL_MODULES) {
    my $module = $moddef->{module};
    my $modver;
    if (eval ' require '.$module.'; $modver = $'.$module.'::VERSION; 1;')
    {
      $modver ||= '(undef)';
      $out .= "module installed: $module, version $modver\n";
    } else {
      $out .= "module not installed: $module ('require' failed)\n";
    }
  }
  return $out;
}

sub long_diagnostics {
  my $summary = "";

  print "checking module dependencies and their versions...\n";

  $EXIT_STATUS = 0;
  $WARNINGS = 0;
  foreach my $moddef (@MODULES) {
    try_module(1, $moddef, \$summary);
  }
  foreach my $moddef (@OPTIONAL_MODULES) {
    try_module(0, $moddef, \$summary);
  }

  print "checking binary dependencies and their versions...\n";

  foreach my $bindef (@BINARIES) {
    try_binary(0, $bindef, \$summary);
  }

  foreach my $bindef (@OPTIONAL_BINARIES) {
    try_binary(0, $bindef, \$summary);
  } 

  print "dependency check complete...\n\n";

  print $summary;
  if ($EXIT_STATUS || $WARNINGS) {
    print "\nwarning: some functionality may not be available,\n".
            "please read the above report before continuing!\n\n";
  }
  return $EXIT_STATUS;
}


sub try_binary {
  my ($required, $bindef, $summref) = @_;

  my $binary_version;
  my $installed = 0;
  my $version_meets_required = 1;
  my $version_meets_recommended = 1;
  my $required_version = $bindef->{version};
  my $recommended_version = $bindef->{recommended_min_version};
  my $errtype;
  my ($command, $output);


  # only viable on unix based systems, so exclude windows, etc. here
  if ($^O =~ /^(mswin|dos|os2)/i) {
    $$summref .= "Warning: Unable to test on this platform for the optional \"$bindef->{'binary'}\" binary\n";
    $errtype = 'is unknown for this platform';
  } else {
    $command = "which $bindef->{'binary'} 2>&1";
    #print "DEBUG: running $command\n";
    $output = `$command`;

    if (!defined $output || $output eq '') {
      $installed = 0;
    } elsif ($output =~ /which: no \Q$bindef->{'binary'}\E in/i) {
      $installed = 0;
    } else {
      #COMMAND APPEARS TO EXIST
      $command = $output;
      chomp ($command);

      $installed = 1;
    }
    #print "DEBUG: $command completed and output parsed\n";
  }


  if ($installed) {
    #SANITIZE THE RETURNED COMMAND JUST IN CASE
    $command =~ s/[^a-z0-9\/]//ig;

    #GET THE VERSION
    $command .= " ";
    if (defined $bindef->{'version_check_params'}) {
      $command .= $bindef->{'version_check_params'};
    }
    $command .= " 2>&1";

    #print "DEBUG: running $command to check the version\n";
    $output = `$command`;

    if (!defined $output) {
      $installed = 0;

    } else {
      if (defined $bindef->{'version_check_regex'}) {
        $output =~ m/$bindef->{'version_check_regex'}/;
        $binary_version = $1;
      }

      #TEST IF VERSION IS GREATER THAN REQUIRED
      if (defined $required_version) {
        $version_meets_required = test_version($binary_version, $required_version);
      }
      if (defined $recommended_version) {
        $version_meets_recommended = test_version($binary_version, $recommended_version);
      }
    }
    #print "DEBUG: $command completd and output parsed\n";
  }

  unless (defined $errtype) {
    if (!$installed) {
      $errtype = "is not installed";
      if ($required_version || $recommended_version) {
        $errtype .= ",\n";
        if ($required_version) {
          $errtype .= "minimum required version is $required_version";
        }
        if ($recommended_version) {
          $errtype .= ", "  if $required_version;
          $errtype .= "recommended version is $recommended_version or higher";
        }
      }
      $errtype .= ".";
    } elsif (!$version_meets_required) {
      $errtype = "is installed ($binary_version),\nbut is below the ".
                 "minimum required version $required_version,\n".
                 "some functionality will not be available.";
      $errtype .= "\nRecommended version is $recommended_version or higher."
        if $recommended_version;
    } elsif (!$version_meets_recommended) {
      $errtype = "is installed ($binary_version),\nbut is below the ".
                 "recommended version $recommended_version,\n".
                 "some functionality may not be available,\n".
                 "and some of the tests in the SpamAssassin test suite may fail.";
    }
  }

  if (defined $errtype) {
    my $pretty_name = $bindef->{alt_name} || $bindef->{binary};
    my $desc = $bindef->{desc}; $desc =~ s/^(\S)/  $1/gm;
    my $pretty_min_version =
      !$required_version ? '' : "(version $required_version) ";

    print "\n", ("*" x 75), "\n";

    if ($errtype =~ /unknown/i) {
      $WARNINGS++;
      print "NOTE: the optional $pretty_name binary $errtype\n";
      $$summref .= "optional binary status could not be determined: $pretty_name\n";
    } 
    elsif ($required) {
      $EXIT_STATUS++;
      warn "\aERROR: the required $pretty_name binary $errtype\n";
      if (!$installed) {
        $$summref .= "REQUIRED binary missing or nonfunctional: $pretty_name\n";
      } elsif (!$version_meets_required) {
        $$summref .= "REQUIRED binary out of date: $pretty_name\n";
      } else {
        $$summref .= "REQUIRED binary older than recommended: $pretty_name\n";
      }
    }
    else {
      $WARNINGS++;
      print "NOTE: the optional $pretty_name binary $errtype\n";
      if (!$installed) {
        $$summref .= "optional binary missing or nonfunctional: $pretty_name\n";
      } elsif (!$version_meets_required) {
        $$summref .= "optional binary out of date: $pretty_name\n";
      } else {
        $$summref .= "optional binary older than recommended: $pretty_name\n";
      }
    }

    print "\n".$desc."\n\n";
  }
}

sub test_version {
  #returns 1 if version1 is equal or greater than $version2
  #returns -1 for an unknown test;
  my ($version1, $version2) = @_;

  my (@version1, @version2);
  my ($count1, $count2, $i, $fail);

  #CAN'T TEST NON NUMERIC VERSIONS
  if (!defined($version1) or !defined($version2) or
      $version1 !~ /^[0-9][0-9.]*\z/ or $version2 !~ /^[0-9][0-9.]*\z/) {
    return -1;
  }

  $fail = 0;

  #check if the numbers have the same number of sub versions
  $_ = $version1;
  $count1 = (s/\.//g);

  #check if the numbers have the same number of sub versions
  $_ = $version2;
  $count2 = (s/\.//g);

  if ($count1 != $count2) {
    #NEED TO ADD .0's to balance the two
    if ($count1 > $count2) {
      for ($i = 0; $i < ($count1-$count2); $i++) {
        $version2 .= '.0';
      }
    } else {
      for ($i = 0; $i < ($count2-$count1); $i++) {
        $version1 .= '.0';
      }
    }
  }

  #print "DEBUG: $version1 vs $version2\n";

  #This would fail comparing 1.4.3 to 1.0.6 because three was less than 6.
  #Need to compare and if greater, on more major versions, skip the less minor versions
  @version1 = split(/\./,$version1);
  @version2 = split(/\./,$version2);

  for ($i = 0; $i < scalar(@version1); $i++) {
    #print "DEBUG: $version1[$i] vs $version2[$i]\n";

    #LESS - NO NEED TO TEST MORE
    if ($version1[$i] < $version2[$i]) {
      $fail++;
      $i = scalar(@version1); 
    #EQUAL - KEEP TESTING
    } elsif ($version1[$i] == $version2[$i]) {
      # Do Nothing
    #GREATER - NO NEED TO TEST MORE
    } else {
      $i = scalar(@version1);
    }
  }

  #print "DEBUG: ".($fail==0)."\n\n";

  return ($fail == 0);
}

sub try_module {
  my ($required, $moddef, $summref) = @_;

  my $module_version;
  my $installed = 0;
  my $version_meets_required = 0;
  my $version_meets_recommended = 0;
  my $required_version = $moddef->{version};
  my $recommended_version = $moddef->{recommended_min_version};

  if (eval "use $moddef->{module} $required_version; 1") {
    $installed = 1;  $version_meets_required = 1;
  } else {
    my $eval_stat;
    if (eval "use $moddef->{module}; 1") {
      $installed = 1;
    } else {
      $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
    # dbg("dependency: $eval_stat");
    };
  }

  if ($installed) {
    eval { $module_version = $moddef->{module}->VERSION };  # wrap just in case
    if (!$recommended_version ||
        ($module_version && $module_version >= $recommended_version)) {
      $version_meets_recommended = 1;
    }
    $module_version = '' if !defined $module_version;
  }

  my $errtype;
  if (!$installed) {
    $errtype = "is not installed";
    if ($required_version || $recommended_version) {
      $errtype .= ",\n";
      if ($required_version) {
        $errtype .= "minimum required version is $required_version";
      }
      if ($recommended_version) {
        $errtype .= ", "  if $required_version;
        $errtype .= "recommended version is $recommended_version or higher";
      }
    }
    $errtype .= ".";
  } elsif (!$version_meets_required) {
    $errtype = "is installed ($module_version),\nbut is below the ".
               "minimum required version $required_version,\n".
               "some functionality will not be available.";
    $errtype .= "\nRecommended version is $recommended_version or higher."
      if $recommended_version;
  } elsif (!$version_meets_recommended) {
    $errtype = "is installed ($module_version),\nbut is below the ".
               "recommended version $recommended_version,\n".
               "some functionality may not be available,\n".
               "and some of the tests in the SpamAssassin test suite may fail.";
  }

  if (defined $errtype) {
    my $pretty_name = $moddef->{alt_name} || $moddef->{module};
    my $desc = $moddef->{desc}; $desc =~ s/^(\S)/  $1/gm;
    my $pretty_min_version =
      !$required_version ? '' : "(version $required_version) ";

    print "\n", ("*" x 75), "\n";

    if ($required) {
      $EXIT_STATUS++;
      warn "\aERROR: the required $pretty_name module $errtype\n";
      if (!$installed) {
        $$summref .= "REQUIRED module missing: $pretty_name\n";
      } elsif (!$version_meets_required) {
        $$summref .= "REQUIRED module out of date: $pretty_name\n";
      } else {
        $$summref .= "REQUIRED module older than recommended: $pretty_name\n";
      }
    }
    else {
      $WARNINGS++;
      print "NOTE: the optional $pretty_name module $errtype\n";
      if (!$installed) {
        $$summref .= "optional module missing: $pretty_name\n";
      } elsif (!$version_meets_required) {
        $$summref .= "optional module out of date: $pretty_name\n";
      } else {
        $$summref .= "optional module older than recommended: $pretty_name\n";
      }
    }

    print "\n".$desc."\n\n";
  }
}

1;
