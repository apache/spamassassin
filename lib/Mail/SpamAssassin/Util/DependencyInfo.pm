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

package Mail::SpamAssassin::Util::DependencyInfo;

use strict;
use warnings;
use bytes;

use vars qw (
  @MODULES @OPTIONAL_MODULES $EXIT_STATUS $WARNINGS
);

my @MODULES = (
{
  'module' => 'Digest::SHA1',
  'version' => '0.00',
  'desc' => 'The Digest::SHA1 module is used as a cryptographic hash for some
  tests and the Bayes subsystem.  It is also used by Razor2.',
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
);

my @OPTIONAL_MODULES = (
{
  module => 'MIME::Base64',
  version => '0.00',
  desc => 'This module is highly recommended to increase the speed with which
  Base64 encoded messages/mail parts are decoded.',
},
{
  module => 'DB_File',
  version => '0.00',
  desc => 'Used to store data on-disk, for the Bayes-style logic and
  auto-whitelist.  *Much* more efficient than the other standard Perl
  database packages.  Strongly recommended.',
},
{
  module => 'Net::SMTP',
  alt_name => 'libnet',
  version => '0.00',
  desc => 'Used when manually reporting spam to SpamCop with "spamassassin -r".',
},
{
  module => 'Mail::SPF',
  version => '0.00',
  desc => 'Used to check DNS Sender Policy Framework (SPF) records to fight email
  address forgery and make it easier to identify spams.  (This is preferred
  over Mail::SPF::Query.)',
},
{
  module => 'Mail::SPF::Query',
  version => '0.00',
  desc => 'Used to check DNS Sender Policy Framework (SPF) records to fight email
  address forgery and make it easier to identify spams.  (Mail::SPF is
  preferred instead of this module.)',
},
{
  module => 'IP::Country::Fast',
  alt_name => 'IP::Country',
  version => '0.00',
  desc => 'Used by the RelayCountry plugin (not enabled by default) to determine
  the domain country codes of each relay in the path of an email.',
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
{
  module => 'Net::Ident',
  version => '0.00',
  desc => 'If you plan to use the --auth-ident option to spamd, you will need
  to install this module.',
},
{
  module => 'IO::Socket::INET6',
  version => '0.00',
  desc => 'This is required if the first nameserver listed in your IP
  configuration or /etc/resolv.conf file is available only via
  an IPv6 address.',
},
{
  module => 'IO::Socket::SSL',
  version => '0.00',
  desc => 'If you wish to use SSL encryption to communicate between spamc and
  spamd (the --ssl option to spamd), you need to install this
  module. (You will need the OpenSSL libraries and use the
  ENABLE_SSL="yes" argument to Makefile.PL to build and run an SSL
  compatibile spamc.)',
},
{
  module => 'Compress::Zlib',
  version => '0.00',
  desc => 'If you wish to use the optional zlib compression for communication
  between spamc and spamd (the -z option to spamc), you need to install
  this module.',
},
{
  module => 'Time::HiRes',
  version => '0.00',
  desc => 'If this module is installed, the processing times are logged/reported
  more precisely in spamd.',
},
{
  module => 'Mail::DomainKeys',
  version => '0.00',
  desc => 'If this module is installed, and you enable the DomainKeys plugin,
  SpamAssassin will perform Domain Key lookups when Domain Key
  information is present in the message headers.  (Note that new versions
  of Mail::DKIM render this module superfluous.)'
},
{
  module => 'Mail::DKIM',
  version => '0.00',
  desc => 'If this module is installed, and you enable the DKIM plugin,
  SpamAssassin will perform DKIM lookups when a DKIM-Signature
  header is present in the message headers.  (New versions of this module
  support both Domain Keys and DKIM, rendering Mail::DomainKeys obsolete.)'
},
{
  module => 'DBI',
  version => '0.00',
  desc => 'If you intend to use SpamAssassin with an SQL database backend for
  user configuration data, Bayes storage, or other storage, you will need
  to have these installed; both the basic DBI module and the driver for
  your database.',
},
{
  module => 'Getopt::Long',
  version => '2.32',        # min version was included in 5.8.0, which works
  desc => 'The "sa-stats.pl" script included in "tools", used to generate
  summary reports from spamd\'s syslog messages, requires this version
  of Getopt::Long or newer.',
},
{
  module => 'LWP::UserAgent',
  version => '0.00',
  desc => 'The "sa-update" script requires this module to make HTTP requests.',
},
{
  module => 'HTTP::Date',
  version => '0.00',
  desc => 'The "sa-update" script requires this module to make HTTP
  If-Modified-Since GET requests.',
},
{
  module => 'Archive::Tar',
  version => '1.23',
  desc => 'The "sa-update" script requires this module to access tar update
  archive files.',
},
{
  module => 'IO::Zlib',
  version => '1.04',
  desc => 'The "sa-update" script requires this module to access compressed
  update archive files.',
},
{
  module => 'Encode::Detect',
  version => '0.00',
  desc => 'If you plan to use the normalize_charset config setting to detect
  charsets and convert them into Unicode, you will need to install
  this module.',
},
);

###########################################################################

=item $f->debug_diagnostics ()

Output some diagnostic information, useful for debugging SpamAssassin
problems.

=cut

sub debug_diagnostics {
  my $out = "diag: perl platform: $] $^O\n";

  # this avoids an unsightly warning due to a shortcoming of Net::Ident;
  # "Net::Ident::_export_hooks() called too early to check prototype at
  # /usr/share/perl5/Net/Ident.pm line 29."   It only needs to be
  # called here.
  eval '
    sub Net::Ident::_export_hooks;
  ';

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

  print $summary;
  if ($EXIT_STATUS || $WARNINGS) {
    print "\nwarning: some functionality may not be available,\n".
            "please read the above report before continuing!\n\n";
  }
  return $EXIT_STATUS;
}

sub try_module {
  my ($required, $moddef, $summref) = @_;

  eval "use $moddef->{module} $moddef->{version};";
  if (!$@) {
    return;
  }

  my $not_installed = 0;
  eval "use $moddef->{module};";
  if ($@) {
    $not_installed = 1;
  }

  my $pretty_name = $moddef->{alt_name} || $moddef->{module};
  my $pretty_version = ($moddef->{version} > 0 ?
                "(version $moddef->{version}) " : "");
  my $desc = $moddef->{desc}; $desc =~ s/^(\S)/  $1/gm;

  my $errtype;
  if ($not_installed) {
    $errtype = "is not installed.";
  } else {
    $errtype = "is installed,\nbut is not an up-to-date version.";
  }

  print "\n", ("*" x 75), "\n";
  if ($required) {
    $EXIT_STATUS++;
    warn "\aERROR: the required $pretty_name ${pretty_version}module $errtype";
    if ($not_installed) {
      $$summref .= "REQUIRED module missing: $pretty_name\n";
    } else {
      $$summref .= "REQUIRED module out of date: $pretty_name\n";
    }
  }
  else {
    $WARNINGS++;
    print "NOTE: the optional $pretty_name ${pretty_version}module $errtype";
    if ($not_installed) {
      $$summref .= "optional module missing: $pretty_name\n";
    } else {
      $$summref .= "optional module out of date: $pretty_name\n";
    }
  }

  print "\n\n".$desc."\n\n";
}

1;
