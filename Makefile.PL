#!/usr/bin/perl
require 5.6.1;

use strict;
use warnings;
use Config;

use ExtUtils::MakeMaker;

# avoid stupid 'Argument "6.30_01" isn't numeric in numeric ge (>=)' warnings;
my $mm_version = eval $ExtUtils::MakeMaker::VERSION;

if ($mm_version < 6.17) {
  die "SpamAssassin Makefile.PL requires at least ExtUtils::MakeMaker v6.17";
}

use constant RUNNING_ON_WINDOWS => ($^O =~ /^(mswin|dos|os2)/oi);
use constant HAS_DBI => eval { require DBI; };

my @ATT_KEYS = (
  # PLEASE READ THE FILE 'PACKAGING' FOR INFORMATION ON THESE VARIABLES.
  #
  # (Current) EU::MMs make a difference between these three possible general
  # install destinations. One can set INSTALLDIRS to 'perl', 'site' or
  # 'vendor' to choose one explicitly (the default is 'site'). They have the
  # following meaning:
  #  * PERL:    Only essential modules shipped with Perl should be installed
  #             there. Don't put SpamAssassin there.
  #  * SITE:    The default. Normal installations via CPAN or from the sources
  #             should use these dirs.
  #  * VENDOR:  A special set of paths for packaged (RPM, deb, portage, ...)
  #             Perl modules. Not always (correctly) used but the intention
  #             is to keep the system from overwriting the modules installed
  #             by the user.
  #
  # See also
  # <http://search.cpan.org/author/MSCHWERN/ExtUtils-MakeMaker-6.16/lib/ExtUtils/MakeMaker.pm#Default_Makefile_Behaviour>
  # <http://www.debian.org/doc/packaging-manuals/perl-policy/ch-module_packages.html#s-vendor_dirs>
  # <http://archive.develooper.com/perl5-porters@perl.org/msg94113.html>
  # <https://bugzilla.redhat.com/bugzilla/show_bug.cgi?id=78053>
  # <http://www.mail-archive.com/makemaker@perl.org/msg00779.html>
  #
  # The options SYSCONFDIR, DATADIR and CONFDIR all support those three
  # possibilities. The '*' in the following comments refers to those.

  'SYSCONFDIR',       # Overwrite all $*SYSCONFDIRs; normally determined
  'PERLSYSCONFDIR',   # based on $*PREFIX.
  'SITESYSCONFDIR',   #
  'VENDORSYSCONFDIR', #

  'DATADIR',          # Overwrite all INSTALL*DATAs; normally determined
  'INSTALLDATA',      # based on $*PREFIX.
  'INSTALLSITEDATA',  #
  'INSTALLVENDORDATA',#

  'CONFDIR',          # Overwrite all INSTALL*CONFs; normally determined
  'INSTALLCONF',      # based on $*SYSCONFDIR.
  'INSTALLSITECONF',  #
  'INSTALLVENDORCONF',#

  'DEFRULESDIR',      # A synonym for 'DATADIR'.
  'LOCALRULESDIR',    # " "       "   'CONFDIR'.

  'LOCALSTATEDIR',    # normally determined based on $*PREFIX.
  'PERLLOCALSTATEDIR', 
  'SITELOCALSTATEDIR', 
  'VENDORLOCALSTATEDIR',

  'PERL_BIN',         # Sets the Perl interpreter used by the scripts.
  'PERL_WARN',        # Can be used to disable warnings in the scripts
  'PERL_TAINT',       # "   "  "    "  "    taint mode for the scripts (DON'T)


  'BUILD_SPAMC'  ,    # Set to 'no' to skip build of spamc.
  'ENABLE_SSL',       # Set to 'yes' to build spamc with SSL support.
  'CONTACT_ADDRESS',  # To not ask for the contact address, use this.
);


sub parse_arg {
  my($val, $name) = (@_);
  if ($val =~ /^($name)=["']?(.*?)["']?$/) {
    return $2;
  } else {
    return undef;
  }
}

sub bool {
  my($val, $def) = (@_, undef, undef);
  $def = 0          unless defined $def;
  return bool($def) unless defined $val;

  $val =~ s/^\s+|\s+$//g;
  return 0 if $val =~ /^(0|N(o)?|Off)$/i;
  return 1 if $val =~ /^(1|Y(es)?|On)$/i;
  return bool($def);
}
sub yesno {
  my($val, $def) = (@_, undef, undef);
  return 'yes' if bool($val, $def);
  return 'no';
}


my %opt = (
  'build_spamc'     => undef,
  'enable_ssl'      => undef,
  'contact_address' => undef,
  'destdir'         => undef,
);
ARGV: foreach (@ARGV) {
  foreach my $key (keys %opt) {
    my $val = parse_arg($_, uc($key));
    if (defined $val) {
      $opt{$key} = $val;
      next ARGV;
    }
  }
}


# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
my %makefile = (
    'NAME'         => 'Mail::SpamAssassin',
    'VERSION_FROM' => 'lib/Mail/SpamAssassin.pm', # finds $VERSION

    # This is not the standard EU::MM array, we use a hash instead (which 
    # will be converted later on).  Use the source file name as the key and
    # the executable as the value.
    'EXE_FILES' => {
      'spamassassin.raw' => 'spamassassin',
      'sa-learn.raw'     => 'sa-learn',
      'sa-update.raw'    => 'sa-update',
      'sa-compile.raw'   => 'sa-compile',
      'sa-awl.raw'       => 'sa-awl',
      'sa-check_spamd.raw' => 'sa-check_spamd',
      'spamc/spamc.c'    => 'spamc/spamc$(EXE_EXT)',
      'spamd/spamd.raw'  => 'spamd/spamd',
    },

    # TODO: the rule compilation is hooked into the build step for "sa-update"
    # as the make target "build_rules".
    # This is kludgy, and it'd be nice to find a cleaner way to do this.

    'MAN1PODS' => {
        'spamassassin'     => '$(INST_MAN1DIR)/spamassassin.$(MAN1EXT)',
        'lib/spamassassin-run.pod' => '$(INST_MAN1DIR)/spamassassin-run.$(MAN1EXT)',
        'sa-learn'         => '$(INST_MAN1DIR)/sa-learn.$(MAN1EXT)',
        'sa-update'        => '$(INST_MAN1DIR)/sa-update.$(MAN1EXT)',
        'sa-compile'       => '$(INST_MAN1DIR)/sa-compile.$(MAN1EXT)',
        'sa-awl'           => '$(INST_MAN1DIR)/sa-awl.$(MAN1EXT)',
        'spamc/spamc.pod'  => '$(INST_MAN1DIR)/spamc.$(MAN1EXT)',
        'spamd/spamd'      => '$(INST_MAN1DIR)/spamd.$(MAN1EXT)',
    },

    'PL_FILES' => { },

    'PMLIBDIRS' => [ 'lib' ],

    'PM_FILTER' => '$(PREPROCESS) -Mconditional -Mvars -DVERSION="$(VERSION)" \
    	-DPREFIX="$(I_PREFIX)" \
	-DDEF_RULES_DIR="$(I_DATADIR)" \
	-DLOCAL_RULES_DIR="$(I_CONFDIR)" \
	-DLOCAL_STATE_DIR="$(I_LOCALSTATEDIR)"',

    'macro' => {
        DATAFILES => 'user_prefs.template languages sa-update-pubkey.txt'
    },

    # be quite explicit about this; afaik CPAN.pm is sensible using this
    # also see CURRENT_PM below
    'PREREQ_PM' => {
        'Digest::SHA1'         => 0,             # 2.0 is oldest tested version
        'File::Spec'           => 0.8,           # older versions lack some routines we need
        'File::Copy'           => 2.02,          # this version is shipped with 5.005_03, the oldest version known to work
        'Pod::Usage'           => 1.10,          # all versions prior to this do seem to be buggy
        'HTML::Parser'         => 3.43,          # the HTML code is based on this parser, older versions have utf-8 bugs
        'Archive::Tar'         => 1.23,          # for sa-update
        'IO::Zlib'             => 1.04,          # for sa-update
        'Mail::DKIM'           => 0.31,
        'Net::DNS'             => (RUNNING_ON_WINDOWS ? 0.46 : 0.34), # bugs in older revs
        'NetAddr::IP'          => 4.010,
        'Sys::Hostname'        => 0,
        'Time::HiRes'          => 0,
        'Time::Local'          => 0,
        'Errno'                => 0,
    },

    'dist' => {
        COMPRESS => 'gzip -9f',
        SUFFIX => 'gz',
        DIST_DEFAULT => 'tardist',

        CI => 'svn commit',
        RCS_LABEL => 'true',
    },

    'clean' => { FILES => join(' ' =>
        'sa-learn', 'sa-update', 'spamassassin', 'sa-compile', 'sa-awl', 'sa-check_spamd',
        
        'spamd/spamd',

        'spamc/spamc$(EXE_EXT)',
        'spamc/spamc.h',
        'spamc/qmail-spamc$(EXE_EXT)',
        'spamc/*.o*', 'spamc/replace/*.o*',
        'spamc/*.so',
        'spamc/Makefile',
        'spamc/config.h', 'spamc/version.h', 'spamc/spamc.h',
        'spamc/config.status', 'spamc/*.cache', 'spamc/config.log',
        'spamd/*spamc*', 'qmail',

        'doc', 'pod2htm*', '*.cache',

	'version.env',

        't/bayessql.cf', 't/do_net', 't/log', 't/sql_based_whitelist.cf',

        'rules/*.pm',

        # don't remove these. they are built from 'rulesrc' in SVN, but
        # in a distribution tarball, they're not
        # 'rules/70_sandbox.cf',
        # 'rules/72_active.cf',

        # this file is no longer built, or used
        'rules/70_inactive.cf',

      )

    },

    'AUTHOR'   => 'The Apache SpamAssassin Project <dev at spamassassin.apache.org>',
    'ABSTRACT' => 'SpamAssassin is an extensible email filter which is used to identify spam',

    # We have only this Makefile.PL and this option keeps MakeMaker from
    # asking all questions twice after a 'make dist*'.
    'NORECURS' => 1,
);

# rules/72_active.cf is built from "rulesrc", but *must* exist before
# WriteMakefile() is called due to shortcomings in MakeMaker.
my @FILES_THAT_MUST_EXIST = qw(
        rules/72_active.cf
    );

# make sure certain optional modules are up-to-date if they are installed
# also see PREREQ_PM above
my %CURRENT_PM = (
    'Net::DNS' => (RUNNING_ON_WINDOWS ? 0.46 : 0.34),
    'Razor2::Client::Agent' => 2.40,
);


# All the $(*MAN1*) stuff is empty/zero if Perl was Configured with -Dman1dir=none;
# however, support site/vendor man1 dirs (bug 5338)
unless($Config{installman1dir}
    || $Config{installsiteman1dir}
    || $Config{installvendorman1dir})
{
  warn "not installing man pages in man1; no man1 dir found";
  delete $makefile{MAN1PODS};
}


# Windows platforms need some adjustments
if (RUNNING_ON_WINDOWS) {
  # Don't build spamd
  delete $makefile{EXE_FILES}{'spamd/spamd.raw'};
  delete $makefile{MAN1PODS}{'spamd/spamd'};
  # building spamc is optional under Win32 because not everyone has compiler
  if (!defined $opt{'build_spamc'}) {
    $opt{'build_spamc'} = bool(prompt(
      "Build spamc.exe (environment must be set up for C compiler)? (y/n)",
      'n'));
  } else {
    $opt{'build_spamc'} = bool($opt{'build_spamc'});
  }
  if (!$opt{'build_spamc'}) {
    delete $makefile{EXE_FILES}{'spamc/spamc.c'};
    delete $makefile{MAN1PODS}{'spamc/spamc.pod'};
  }
}


$makefile{'macro'}{'ENABLE_SSL'} = yesno($opt{'enable_ssl'});

if (!defined $opt{'contact_address'}) {
  $opt{'contact_address'} = prompt(
    "What email address or URL should be used in the suspected-spam report\n".
    "text for users who want more information on your filter installation?\n".
    "(In particular, ISPs should change this to a local Postmaster contact)\n".
    "default text:", "the administrator of that system"
  );
  print "\n";
}
$makefile{'macro'}{'CONTACT_ADDRESS'} = $opt{'contact_address'};

print 
'NOTE: settings for "make test" are now controlled using "t/config.dist". 
See that file if you wish to customise what tests are run, and how.

';

# check optional module versions
use lib 'lib';
use Mail::SpamAssassin::Util::DependencyInfo;
if (Mail::SpamAssassin::Util::DependencyInfo::long_diagnostics() != 0) {
  # missing required module?  die!
  # bug 5908: http://cpantest.grango.org/wiki/CPANAuthorNotes says
  # we should exit with a status of 0, but without creating Makefile
  exit 0;
}

foreach my $file (@FILES_THAT_MUST_EXIST) {
  open (TOUCH, ">>$file") or die "cannot touch '$file'";
  close TOUCH;
}

#######################################################################

# bug 6131
($mm_version >= 6.46) and $makefile{META_MERGE} = {
  license => 'apache',

  resources => {
    license     => 'http://www.apache.org/licenses/LICENSE-2.0.html',
    homepage    => 'http://spamassassin.apache.com/',
    bugtracker  => 'https://issues.apache.org/SpamAssassin/',
    repository  => 'http://svn.apache.org/repos/asf/spamassassin/',
    MailingList => 'http://wiki.apache.org/spamassassin/MailingLists',
  },

  recommends => {
    'MIME::Base64' =>              0,
    'DB_File' =>                   0,
    'Net::SMTP' =>                 0,
    'Mail::SPF' =>                 0,
    'Geo::IP' =>                   0,
    'Razor2::Client::Agent' =>     2.61,
    'Net::Ident' =>                0,
    'IO::Socket::INET6' =>         0,
    'IO::Socket::SSL' =>           0,
    'Compress::Zlib' =>            0,
    'Mail::DKIM' =>                0.37,
    'DBI' =>                       0,
    'Getopt::Long' =>              2.32,
    'LWP::UserAgent' =>            0,
    'HTTP::Date' =>                0,
    'Archive::Tar' =>              1.23,
    'IO::Zlib' =>                  1.04,
    'Encode::Detect' =>            0
  }
};

#######################################################################

# Now finish the meta hash and dump the Makefile
$makefile{EXE_FILES} = [ values %{$makefile{EXE_FILES}} ];
$makefile{AUTHOR} =~ s/(<.+) at (.+>)/$1\@$2/;
WriteMakefile(%makefile);
print "Makefile written by ExtUtils::MakeMaker $mm_version\n";

#######################################################################

package MY;

use vars qw(
  $MY_GLOBALS_ARE_SANE
  $RUNNING_ON_WINDOWS
  @REPOSITORIES

  $MACRO_RE
  $EQ_RE
  $EQ

  $SELF
);

# For some reason initializing the vars on the global scope doesn't work;
# guess its some weird Perl behaviour in combination with bless().
sub init_MY_globals {
  my $self = shift;

  # Keep a reference to ourselves so we don't have to feed it to the helper
  # scripts.
  $SELF = $self;

  return if $MY_GLOBALS_ARE_SANE;
  $MY_GLOBALS_ARE_SANE = 1;

  # (Current) EU::MMs make a difference between these three possible general
  # install destinations. See also
  # <http://archive.develooper.com/perl5-porters@perl.org/msg94113.html>
  # <https://bugzilla.redhat.com/bugzilla/show_bug.cgi?id=78053>
  # <http://www.mail-archive.com/makemaker@perl.org/msg00779.html>
  # <http://www.debian.org/doc/packaging-manuals/perl-policy/ch-module_packages.html#s-vendor_dirs>
  @REPOSITORIES = qw(
    PERL
    SITE
    VENDOR
  );

  # Macro names follow this RE -- at least stricly enough for our purposes.
  $MACRO_RE = qr/[A-Z0-9_]+/;
  # Normally macros are assigned via FOO = bar. But the part with the equal
  # sign might differ from platform to platform. So we use this RE:
  $EQ_RE = qr/\s*:?=\s*/;
  # To assign or own macros we'll follow the first assignment string we find;
  # normally " = ".
  $EQ = undef;

  # Inherit our Windows-Flag.
  $RUNNING_ON_WINDOWS = ::RUNNING_ON_WINDOWS;
}

# Unset $SELF to avoid any leaking memory.
sub clean_MY_globals {
  my $self = shift;

  $SELF = undef;
}

sub set_EQ_from_line {
  my($line) = (@_);

  return if defined($EQ);

  $line =~ /\S(${EQ_RE})/;
  $EQ = $1;
}


# Converts a version represented as a float to a real three-part version,
# eg.:
#  5.006001 -> 5.6.1
#  5.005_03 -> 5.5.30
#
# The first parameter should be a version, in what format ever.
sub float_to_version {
  my($ver) = (@_);

  if ($ver =~ /^\d\.\d+$/) {
    $ver   =  sprintf("%1.6f", $ver);
    $ver   =~ s/[.0]+([1-9]+)/.$1/g;
  }

  return $ver;
}


# Generates a Makefile-reference to another macro; something like $(FOO).
#
# The first and only parameter should be the name of the referred macro,
# eg. 'FOO' (will return '$(FOO)').
sub macro_ref {
  my($name) = (@_);

  return sprintf('$(%s)', $name);
}

# Generates a line which defines a Makefile macro. Something like FOO = bar.
# The line is *not* followed by a newline!
#
# The first parameter must be the name of the macro. The second is optional.
# If it is omitted, the value set in the current EU::MM instance is used.
sub macro_def {
  my($name, $val) = (@_, undef);
  my $MUST_NOT_HAPPEN = "THIS MUST NOT HAPPEN. PLEASE REPORT A BUG VIA <https://issues.apache.org/SpamAssassin/>";
  die $MUST_NOT_HAPPEN  unless defined $name;
  die $MUST_NOT_HAPPEN  unless defined $EQ;
  $val = $SELF->{$name} unless defined $val;

  return $name . $EQ . $val;
}

# Returns true if the given line defines a macro.
#
# The first parameter must be the line to inspect. With the second optional
# parameter the name of a specific macro might be given. If its omitted, any
# macro matching the MACRO_RE pattern will fit.
sub line_has_macro_def {
  my($line, $name) = (@_, undef);
  $name = $MACRO_RE unless defined $name;

  return $line =~ /^($name)${EQ_RE}/;
}

# Reads the name of the macro defined on the given line.
#
# The first parameter must be the line to be expected. If the line doesn't
# contain a macro definition, weird things may happen. So check with
# line_has_macro_def() before!
sub get_macro_name_from_line {
  my($line) = (@_);

  $line =~ /^(${MACRO_RE})${EQ_RE}/;
  return $1;
}

# Reads the value of the given macro from the current instance of EU::MM.
#
# The first parameter must be the name of a macro.
sub get_macro {
  my($name) = (@_);

  return $SELF->{$name};
}

# Reads the value of the given macro from the current instance of EU::MM and
# expands all contained macros. So reading BAZ with these declarations
#   FOO = blah
#   BAR = $(FOO)
#   BAZ = $(BAR)
# gives 'blah'.
#
# The first parameter must be the name of a macro.
sub get_expanded_macro {
  my($name) = (@_);

  my($val);
  $val = get_macro($name);
  # Now expand all macros...
  while ($val =~ s/\Q$(\E(${MACRO_RE})\Q)\E/$SELF->{$1} || ''/ge) {};

  return $val;
}

# Sets the value of the macro with the given name to the given value in the
# current instance of EU::MM. Just sets, doesn't write to the Makefile!
#
# The first parameter must be the macro's name, the second the value.
sub set_macro {
  my($name, $val) = (@_);

  $SELF->{$name} = $val;
}


# Returns the actual "repository" name used in macro names; the point is that
# EU::MM leaves out the name if the repository is 'PERL'. But only for macros
# which don't start with the repository name (like the INSTALL* ones). So the
# following mapping should be made:
#   PERLPREFIX      -> PERLPREFIX
#   PERLSYSCONFDIR  -> PERLSYSCONFDIR
#   INSTALLSITECONF -> INSTALLSITECONF
#   INSTALLPERLCONF -> INSTALLCONF
# Actually, its a bit more complex than that but we follow that simple mapping
# for our vars; one also has to know when to call this function and when not.
# If the second parameter is set, always the PERL variant is used.
sub repository {
  my($repository, $default) = (@_);

  return '' if $default;
  return '' if $repository eq 'PERL';
  return $repository;
}


# This routine determines the correct SYSCONFDIR to use for the given
# repository.
#
# The first parameter must be one value from @REPOSITORIES.
#
# *SYSCONFDIR can be overwritten with:
#   *SYSCONFDIR
#   SYSCONFDIR
# If none of those is specified, it will chose an FHS-compliant dir
# based on the corresponding *PREFIX:
#   *PREFIX     *SYSCONFDIR
#   /usr        /etc
#   /usr/local  /etc
#   /opt/*      /etc/opt
#   /foo/*      /foo/*/etc
sub _set_macro_SYSCONFDIR {
  my($repository) = (@_);

  my($macro);
  $macro = $repository . "SYSCONFDIR";

  # Is this macro already set?
  return if get_macro($macro);

  # Is this macro supposed to be overwritten?
  if (get_macro('SYSCONFDIR')) {
    set_macro($macro, macro_ref('SYSCONFDIR'));
    return;
  }

  my($rprefix);
  $rprefix = get_expanded_macro("${repository}PREFIX");

  # Set the default, depending on the corresponding full PREFIX
  set_macro($macro,
    ($rprefix =~ m{^$})                ? ''         :
    ($rprefix =~ m{^/usr(/local)?/?$}) ? '/etc'     :
    ($rprefix =~ m{^/opt(/|$)})        ? '/etc/opt' :
    macro_ref("${repository}PREFIX") . '/etc'
  );
}

# This routine determines the correct LOCALSTATEDIR to use for the given
# repository.
#
# The first parameter must be one value from @REPOSITORIES.
#
# *LOCALSTATEDIR can be overwritten with:
#   *LOCALSTATEDIR
#   LOCALSTATEDIR
# If none of those is specified, it will chose an FHS-compliant dir
# based on the corresponding *PREFIX:
#   *PREFIX     *LOCALSTATEDIR
#   /usr        /etc
#   /usr/local  /etc
#   /opt/*      /etc/opt
#   /foo/*      /foo/*/etc
sub _set_macro_LOCALSTATEDIR {
  my($repository) = (@_);

  my($macro);
  $macro = $repository . "LOCALSTATEDIR";

  # Is this macro already set?
  return if get_macro($macro);

  # Is this macro supposed to be overwritten?
  if (get_macro('LOCALSTATEDIR')) {
    set_macro($macro, macro_ref('LOCALSTATEDIR'));
    return;
  }

  my($rprefix);
  $rprefix = get_expanded_macro("${repository}PREFIX");

  # Set the default, depending on the corresponding full PREFIX
  set_macro($macro,
    ($rprefix =~ m{^$})                ? ''                      :
    ($rprefix =~ m{^/usr(/local)?/?$}) ? '/var/lib/spamassassin' :
    ($rprefix =~ m{^/opt(/|$)})        ? '/var/opt/spamassassin' :
    macro_ref("${repository}PREFIX") . '/var/spamassassin'
  );
}

# This routine determines the correct INSTALLDATADIR (aka DEFRULESDIR)
# to use for the given repository.
#
# The first parameter must be one value from @REPOSITORIES.
#
# INSTALL*DATADIR can be overwritten with:
#   INSTALL*DATADIR
#   DATADIR
#   DEFRULESDIR
# If none of those is specified, it will chose an FHS-compliant dir,
# namely *PREFIX/share/spamassassin.
sub _set_macro_DATADIR {
  my($repository) = (@_);

  my($macro);
  $macro = "INSTALL" . repository($repository) . "DATA";

  # Is this macro already set?
  return if get_macro($macro);

  # Is this macro supposed to be overwritten?
  foreach my $omacro (qw(DATADIR DEFRULESDIR)) {
    if (get_macro($omacro)) {
      set_macro($macro, get_macro($omacro));
      return;
    }
  }

  # Set the default value based on the corresponding PREFIX
  set_macro($macro,
    macro_ref("${repository}PREFIX") . '/share/spamassassin'
  );
}

# This routine determines the correct INSTALLCONFDIR (aka LOCALRULESDIR)
# to use for the given repository.
#
# The first parameter must be one value from @REPOSITORIES.
#
# INSTALL*CONFDIR can be overwritten with:
#   INSTALL*CONFDIR
#   CONFDIR
#   LOCALRULESDIR
# If none of those is specified, it will chose an FHS-compliant dir,
# namely *SYSCONFDIR/mail/spamassassin.
sub _set_macro_CONFDIR {
  my($repository) = (@_);

  my($macro);
  $macro = "INSTALL" . repository($repository) . "CONF";

  # Is this macro already set?
  return if get_macro($macro);

  # Is this macro supposed to be overwritten?
  foreach my $omacro (qw(CONFDIR LOCALRULESDIR)) {
    if (get_macro($omacro)) {
      set_macro($macro, get_macro($omacro));
      return;
    }
  }

  # Set the default value based on the corresponding SYSCONFDIR
  set_macro($macro,
    macro_ref("${repository}SYSCONFDIR") . '/mail/spamassassin'
  );
}

# This routine determines the correct value for PERL_BIN.
#
# There are no parameters.
#
# If PERL_BIN wasn't set at the command line, it will fall back to
# $(FULLPERL) which should refer to the current Perl interpreter.
sub _set_macro_PERL_BIN {

  return if get_macro('PERL_BIN');
  set_macro('PERL_BIN', macro_ref('FULLPERL'));
}

# This is a helper routine for PERL_WARN and PERL_TAINT.
#
# The first parameter must be either 'WARN' or 'TAINT'.
sub _set_macro_PERL_yesno {
  my($macro) = (@_);

  my($val);
  $macro = 'PERL_' . $macro;
  $val   = "";
  if (get_macro($macro)) {
    $val = ::yesno(get_macro($macro));
  }

  set_macro($macro, $val);
}

# This routine sets the value for PERL_WARN.
#
# There are no parameters.
#
# If PERL_WARN wasn't set at the command line, PERL_WARN will be left
# empty (ie: the default is used). If it was set, the value is fed to
# yesno().
sub _set_macro_PERL_WARN {
  _set_macro_PERL_yesno('WARN');
}

# This routine sets the value for PERL_TAINT.
#
# There are no parameters.
#
# If PERL_TAINT wasn't set at the command line, PERL_TAINT will be left
# empty (ie: the default is used). If it was set, the value is fed to
# yesno().
sub _set_macro_PERL_TAINT {
  _set_macro_PERL_yesno('TAINT');
}

# This routine sets the value for PREPROCESS.
#
# There are no parameters.
#
# If PREPROCESS wasn't set at the command line, it chooses our default
# perl-called preprocessor.
sub _set_macro_PREPROCESS {

  return if get_macro('PREPROCESS');
  set_macro('PREPROCESS', join(' ', macro_ref('PERL_BIN'), qq{build/preprocessor}));
}

# This routine sets the value for CONFIGURE (spamc only).
#
# There are no parameters.
#
# If CONFIGURE wasn't set at the command line, it chooses our default
# perl-wrapped configure.
sub _set_macro_CONFIGURE {

  return if get_macro('CONFIGURE');
  set_macro('CONFIGURE', join(' ', macro_ref('PERL_BIN'), qq{spamc/configure.pl}));
}

# This routine sets the value for the SYMLINK command.
#
# There are no parameters.
#
# $(SYMLINK) calls Perl's symlink() function if available, else falls back 
# to $(CP).
sub _set_macro_SYMLINK {

  return if get_macro('SYMLINK');
  
  if (eval { symlink("", "") or 1 }) {
    my $code = q{symlink((splitpath($ARGV[0]))[2], $ARGV[1]) || die qq{$!\n}};
    $code =~ s/(\$)/$1$1/g;
    $code = qq{'$code'};
    set_macro('SYMLINK', join(' ', macro_ref('PERL_BIN'), q{-MFile::Spec::Functions=splitpath}, q{-e}, $code));
  }
  else {
    set_macro('SYMLINK', macro_ref('CP'));
  }
}


# Override the libscan routine so it skips SVN/CVS stuff and some common
# patch/backup extensions.
sub MY::libscan {
  my $self = shift;
  my($path) = @_;
  init_MY_globals($self);

  return q{} if $path =~ m{
                  (^|/)(CVS|\.svn)(/|$)|
                  [/.](orig|old|rej|r\d+|diff|patch|bak|backup|mine|my|swp)$
                }ix;

  clean_MY_globals($self);
  return $path; #/
}

# Override the install routine to add our additional install dirs and
# hack DESTDIR support into old EU::MMs.
sub MY::install {
  my $self = shift;
  my @code = split(/\n/, $self->SUPER::install(@_));
  init_MY_globals($self);

  foreach (@code) {
    # Add our install targets as a dependency to all top-level install targets
    s/^(install(?:_[a-z]+)?\s*::?\s*.*)$/$1 conf__install data__install/;
  }

  clean_MY_globals($self);
  return join("\n", @code);
}


# Now override the constants routine to add our own macros.
sub MY::constants {
  my $self = shift;
  my @code = split(/\n/, $self->SUPER::constants(@_));
  init_MY_globals($self);

  foreach my $line (@code) {
    # Skip comments
    next if $line =~ /^\s*#/;
     # Skip everything which isn't a var assignment.
    next unless line_has_macro_def($line);

    # Store the assignment string if necessary.
    set_EQ_from_line($line);

    # Store a nicer version string for later use.
    if (line_has_macro_def($line, 'VERSION')) {
      get_macro('VERSION') =~ /^(\d)\.(\d\d\d)_?(\d\d\d)/;
      set_macro('VERSION_COOL', join(".", $1*1, $2*1, $3*1));
      $line .= "\n" . macro_def('VERSION_COOL');
    }

    # Add some "dummy" (PERL|SITE|VENDOR)PREFIX macros for later use (only if
    # necessary for old EU::MMs of course)
    if (line_has_macro_def($line, 'PREFIX')) {
      foreach my $r (@REPOSITORIES) {
        my $rprefix = "${r}PREFIX";

        if (!defined(get_macro($rprefix))) {
          set_macro($rprefix, macro_ref('PREFIX'));
          $line .= "\n" . macro_def($rprefix);
        }
      }
    }
  }
  push(@code, qq{});

  # Add some additional target dirs
  {
    set_macro('SYSCONFDIR', "") unless get_macro('SYSCONFDIR');
    set_macro('LOCALSTATEDIR', "") unless get_macro('LOCALSTATEDIR');

    # Determine the correct settings for each repository...
    foreach my $r (@REPOSITORIES) {
      _set_macro_SYSCONFDIR($r);
      _set_macro_LOCALSTATEDIR($r);
      _set_macro_DATADIR($r);
      _set_macro_CONFDIR($r);
    }

    # ... and add it to the Makefile.
    push(@code, qq{});
    push(@code, qq{# Where to install config files});
    push(@code, macro_def('SYSCONFDIR'));
    foreach my $r (@REPOSITORIES) {
      push(@code, macro_def($r . 'SYSCONFDIR'));
    }

    push(@code, qq{});
    push(@code, qq{# Where to install local state files});
    push(@code, macro_def('LOCALSTATEDIR'));
    foreach my $r (@REPOSITORIES) {
      push(@code, macro_def($r . 'LOCALSTATEDIR'));
    }

    foreach my $m (qw(DATA CONF)) {
      foreach my $r (@REPOSITORIES) {
        my $macro = 'INSTALL' . repository($r) . $m;
        # The INSTALL* macros.
        push(@code, macro_def($macro));
        # The DESTINSTALL* macros.
        push(@code, macro_def('DEST' . $macro, macro_ref('DESTDIR') . macro_ref($macro)));
      }
    }
  }

  # Set the PERL_* stuff
  {
    _set_macro_PERL_BIN;
    _set_macro_PERL_WARN;
    _set_macro_PERL_TAINT;

    # Add it to the Makefile.
    push(@code, qq{});
    push(@code, qq{# Some details about our Perl});
    foreach my $m (qw(BIN WARN TAINT)) {
      push(@code, macro_def('PERL_' . $m));
    }
  }

  # Set the preprocessor and configure scripts
  {
    _set_macro_PREPROCESS;
    _set_macro_CONFIGURE;
    _set_macro_SYMLINK;

    # Add it to the Makefile.
    push(@code, qq{});
    push(@code, macro_def('PREPROCESS'));
    push(@code, macro_def('CONFIGURE'));
    push(@code, macro_def('SYMLINK'));
  }

  # Set some additional helper/shortcut macros; the B_FOO are the ones which
  # can be temporary locations if DESTDIR is used, I_FOO are the final 
  # destinations.
  {
    my($repository);
    $repository = uc($SELF->{INSTALLDIRS}) || 'SITE';

    # For these the install paths are needed only.
    foreach my $macro (qw(PREFIX SYSCONFDIR LOCALSTATEDIR)) {
      push(@code, macro_def('I_' . $macro,
                    macro_ref($repository . $macro)));
    }
    # For the following we need bot the B_- and the I_-variants.  But the
    # SCRIPT macro is the same for all repositories.
    foreach my $macro (qw(SCRIPT DATA CONF LIB)) {
      push(@code, macro_def('I_' . $macro . 'DIR',
                    macro_ref('INSTALL' . repository($repository, $macro eq 'SCRIPT') . $macro)));

      push(@code, macro_def('B_' . $macro . 'DIR',
                    macro_ref('DESTINSTALL' . repository($repository, $macro eq 'SCRIPT') . $macro)));
    }
  }

  clean_MY_globals($self);
  return join("\n", @code);
}

# Override some vars in the dist section.
sub MY::dist {
  my $self = shift;
  my @code = split(/\n/, $self->SUPER::dist(@_));
  init_MY_globals($self);

  foreach my $line (@code) {
    # Skip comments
    next if $line =~ /^\s*#/;
     # Skip everything which isn't a var assignment.
    next unless line_has_macro_def($line);

    # Store the assignment string if necessary.
    set_EQ_from_line($line);
    
    if (line_has_macro_def($line, 'DISTVNAME') && get_macro('VERSION_COOL')) {
      set_macro('DISTVNAME', '$(DISTNAME)-$(VERSION_COOL)');
      $line = macro_def('DISTVNAME');
    }
  }

  clean_MY_globals($self);
  return join("\n", @code);
}

sub MY::postamble {
  my $self = shift;
  my $code = "";
  init_MY_globals($self);

  $code .= <<'  EOD';

FIXVARS		= -Mvars \
		  -DVERSION="$(VERSION)" \
		  -DPREFIX="$(I_PREFIX)" \
		  -DDEF_RULES_DIR="$(I_DATADIR)" \
		  -DLOCAL_RULES_DIR="$(I_CONFDIR)" \
		  -DLOCAL_STATE_DIR="$(I_LOCALSTATEDIR)" \
		  -DINSTALLSITELIB="$(I_LIBDIR)" \
		  -DCONTACT_ADDRESS="$(CONTACT_ADDRESS)"

FIXBANG		= -Msharpbang \
                  -Mconditional \
		  -DPERL_BIN="$(PERL_BIN)" \
		  -DPERL_WARN="$(PERL_WARN)" \
		  -DPERL_TAINT="$(PERL_TAINT)"

spamassassin: spamassassin.raw
	$(PREPROCESS) $(FIXBYTES) $(FIXVARS) $(FIXBANG) -m$(PERM_RWX) -i$? -o$@

sa-learn: sa-learn.raw
	$(PREPROCESS) $(FIXBYTES) $(FIXVARS) $(FIXBANG) -m$(PERM_RWX) -i$? -o$@

sa-update: sa-update.raw build_rules
	$(PREPROCESS) $(FIXBYTES) $(FIXVARS) $(FIXBANG) -m$(PERM_RWX) -isa-update.raw -osa-update

sa-compile: sa-compile.raw
	$(PREPROCESS) $(FIXBYTES) $(FIXVARS) $(FIXBANG) -m$(PERM_RWX) -isa-compile.raw -osa-compile

sa-awl: sa-awl.raw
	$(PREPROCESS) $(FIXBYTES) $(FIXVARS) $(FIXBANG) -m$(PERM_RWX) -isa-awl.raw -osa-awl

sa-check_spamd: sa-check_spamd.raw
	$(PREPROCESS) $(FIXBYTES) $(FIXVARS) $(FIXBANG) -m$(PERM_RWX) -isa-check_spamd.raw -osa-check_spamd

spamd/spamd: spamd/spamd.raw
	$(PREPROCESS) $(FIXBYTES) $(FIXVARS) $(FIXBANG) -m$(PERM_RWX) -i$? -o$@

build_rules: 
	$(PERL) build/mkrules --exit_on_no_src --src rulesrc --out rules --manifest MANIFEST --manifestskip MANIFEST.SKIP

SPAMC_MAKEFILE  = spamc/Makefile
MAKE_SPAMC      = $(MAKE) -f $(SPAMC_MAKEFILE)
MAKE_SPAMC_OLD  = $(MAKE) SOURCE=$< TARGET=$@ spamc_has_moved

SPAMC_SRC       = spamc/spamc.c spamc/utils.c
QSPAMC_SRC      = spamc/qmail-spamc.c spamc/utils.c
LIBSPAMC_SRC    = spamc/libspamc.c spamc/utils.c

$(SPAMC_MAKEFILE): $(SPAMC_MAKEFILE).in $(SPAMC_MAKEFILE).win spamc/spamc.h.in
	$(CONFIGURE) --prefix="$(I_PREFIX)" --sysconfdir="$(I_CONFDIR)" --datadir="$(I_DATADIR)" --enable-ssl="$(ENABLE_SSL)"

spamc_has_moved:
	$(NOECHO) echo "***"
	$(NOECHO) echo "*** spamc now has its own directory: $(TARGET) is $(SOURCE)"
	$(NOECHO) echo "***"
	$(PERL) -MFile::Spec -MFile::Copy \
	  -e "copy(q{$(SOURCE)}, q{$(TARGET)});"

spamc/libspamc.so: $(SPAMC_MAKEFILE) $(LIBSPAMC_SRC)
	$(MAKE_SPAMC) $@

spamd/libspamc.so: spamc/libspamc.so
	$(MAKE_SPAMC_OLD)

spamc/libsslspamc.so: $(SPAMC_MAKEFILE) $(LIBSPAMC_SRC)
	$(MAKE_SPAMC) $@

spamd/libsslspamc.so: spamc/libsslspamc.so
	$(MAKE_SPAMC_OLD)

spamc/spamc$(EXE_EXT): $(SPAMC_MAKEFILE) $(SPAMC_SRC) $(LIBSPAMC_SRC)
	$(MAKE_SPAMC) $@

spamd/spamc$(EXE_EXT): spamc/spamc$(EXE_EXT)
	$(MAKE_SPAMC_OLD)
	$(CHMOD) $(PERM_RWX) $@

spamc/qmail-spamc$(EXE_EXT): $(SPAMC_MAKEFILE) $(QSPAMC_SRC)
	$(MAKE_SPAMC) $@

qmail/qmail-spamc$(EXE_EXT): spamc/qmail-spamc$(EXE_EXT)
	$(MKPATH) qmail
	$(MAKE_SPAMC_OLD)
	$(CHMOD) $(PERM_RWX) $@

# needs to be added to MY::install if used
#bin__install: $(INST_SCRIPT)/sa-filter
#        # $(RM_F) $(B_SCRIPTDIR)/spamassassin
#        # $(SYMLINK) $(INST_SCRIPT)/sa-filter $(B_SCRIPTDIR)/spamassassin

conf__install:
	-$(MKPATH) $(B_CONFDIR)
	$(PERL) -MFile::Copy -e "copy(q{rules/local.cf}, q{$(B_CONFDIR)/local.cf}) unless -f q{$(B_CONFDIR)/local.cf}"
	$(PERL) -MFile::Copy -e "copy(q{rules/init.pre}, q{$(B_CONFDIR)/init.pre}) unless -f q{$(B_CONFDIR)/init.pre}"
	$(PERL) -MFile::Copy -e "copy(q{rules/v310.pre}, q{$(B_CONFDIR)/v310.pre}) unless -f q{$(B_CONFDIR)/v310.pre}"
	$(PERL) -MFile::Copy -e "copy(q{rules/v312.pre}, q{$(B_CONFDIR)/v312.pre}) unless -f q{$(B_CONFDIR)/v312.pre}"
	$(PERL) -MFile::Copy -e "copy(q{rules/v320.pre}, q{$(B_CONFDIR)/v320.pre}) unless -f q{$(B_CONFDIR)/v320.pre}"
	$(PERL) -MFile::Copy -e "copy(q{rules/v330.pre}, q{$(B_CONFDIR)/v330.pre}) unless -f q{$(B_CONFDIR)/v330.pre}"
	$(PERL) -MFile::Copy -e "copy(q{rules/v340.pre}, q{$(B_CONFDIR)/v340.pre}) unless -f q{$(B_CONFDIR)/v340.pre}"
	$(PERL) -MFile::Copy -e "copy(q{rules/v341.pre}, q{$(B_CONFDIR)/v341.pre}) unless -f q{$(B_CONFDIR)/v341.pre}"
  

data__install:
	-$(MKPATH) $(B_DATADIR)
	$(PERL) -e "map unlink, <$(B_DATADIR)/*>"
	$(PREPROCESS) $(FIXVARS) -m$(PERM_RW) -Irules -O$(B_DATADIR) $(DATAFILES)
	$(CHMOD) $(PERM_RWX) $(B_DATADIR)

text_html_doc: made-doc-stamp
	$(NOOP)

doc:
	$(MKPATH) $@

made-doc-stamp: doc $(MAN1PODS) $(MAN3PODS) $(EXTRAPODS)
	$(PERL) build/convert_pods_to_doc $(MAN1PODS) $(MAN3PODS) $(EXTRAPODS)
	$(TOUCH) made-doc-stamp
	$(RM_F) pod2htm*


version.env: lib/Mail/SpamAssassin.pm Makefile
	$(RM_F) $@
	$(PERL) -Ilib -MMail::SpamAssassin -e 'printf("FULL_VERSION=%s\n", Mail::SpamAssassin::Version())' >> $@
	$(PERL) -e 'print "DIST_VERSION=$(VERSION_COOL)\n"' >> $@
	$(PERL) -e 'print "CPAN_VERSION=$(VERSION)\n"' >> $@


manifest_skip:
	sort -f < MANIFEST.SKIP > MANIFEST.SKIP.tmp
	mv MANIFEST.SKIP.tmp MANIFEST.SKIP

sysreport:
	$(NOECHO) $(PERL) tools/sysreport CC=$(CC) PERL=$(PERL) PERL_BIN=$(PERL_BIN)

  EOD

  clean_MY_globals($self);
  return $code;
}
