#!/usr/bin/perl
require 5.6.1;

use strict;
use warnings;
use Config;

use ExtUtils::MakeMaker 5.45;

use constant RUNNING_ON_WINDOWS => ($^O =~ /^(mswin|dos|os2)/oi);


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

  'PERL_BIN',         # Sets the Perl interpreter used by the scripts.
  'PERL_VERSION',     # Some parts in SpamAssassin were dependant on the version
  'PERL_WARN',        # Can be used to disable warnings in the scripts
  'PERL_TAINT',       # "   "  "    "  "    taint mode for the scripts (DON'T)


  'ENABLE_SSL',       # Set to 'yes' to build spamc with SSL support.
  'CONTACT_ADDRESS',  # To not ask for the contact address, use this.
  'RUN_NET_TESTS',    # To not ask whether net tests should be run, use this.
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
  'enable_ssl'      => undef,
  'contact_address' => undef,
  'run_net_tests'   => undef,
  'destdir'         => undef,
  '__cruft'         => undef,
  'ignore_cruft'    => undef,
);
ARGV: foreach (@ARGV) {
  foreach my $key (keys %opt) {
    my $val;

    $val = parse_arg($_, uc($key));
    if (defined $val) {
      $opt{$key} = $val;
      next ARGV;
    }

    if (defined parse_arg($_, qr/INST_(?:PREFIX|SITELIB|SYSCONFDIR)|[A-Z_]+_RULES_DIR/)) {
      $opt{'__cruft'} = 1;
    }
  }
}


# Gather some information about what EU::MM offers and/or needs
my(
  $mm_version,
  $mm_knows_destdir,
  $mm_has_destdir,
  $mm_has_good_destdir,
  $mm_needs_destdir,
);

# Store the version for later use
$mm_version          = $ExtUtils::MakeMaker::VERSION;

# MakeMaker prior to 6.11 doesn't support DESTDIR which is needed for
# packaging with builddir!=destdir. See bug 2388.
$mm_knows_destdir    = $ExtUtils::MakeMaker::Recognized_Att_Keys{DESTDIR};
$mm_has_good_destdir = $mm_version >= 6.11;
# Add DESTDIR hack only if it's requested (and necessary)
$mm_needs_destdir    = $opt{'destdir'} && !$mm_has_destdir;
$mm_has_destdir      = $mm_knows_destdir || $mm_needs_destdir;
push(@ATT_KEYS, 'DESTDIR') if $mm_needs_destdir;

# Now make EU::MM understand our extended vars
foreach my $key (@ATT_KEYS) {
  $ExtUtils::MakeMaker::Recognized_Att_Keys{$key} = 1;
}


# Gather the rules files in the range 00-69; we do this in perl because it's more portable
my @datafiles = map { s,^rules/,,; $_ } (<rules/*.cf>);
my $datafiles = join(' ', (grep { /^[0-6][0-9]_/ } @datafiles), qw(user_prefs.template triplets.txt languages));


# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
my %makefile = (
    'NAME'         => 'Mail::SpamAssassin',
    'VERSION_FROM' => 'lib/Mail/SpamAssassin.pm', # finds $VERSION

    'EXE_FILES'	=> [
        'spamassassin', 'sa-learn',
        'spamd/spamc$(EXE_EXT)',
        'spamd/spamd',
    ],

    'MAN1PODS' => {
        'spamassassin'    => '$(INST_MAN1DIR)/spamassassin.$(MAN1EXT)',
        'sa-learn'        => '$(INST_MAN1DIR)/sa-learn.$(MAN1EXT)',
        'spamd/spamc.pod' => '$(INST_MAN1DIR)/spamc.$(MAN1EXT)',
        'spamd/spamd'     => '$(INST_MAN1DIR)/spamd.$(MAN1EXT)',
    },

    'PL_FILES' => { },

    'PMLIBDIRS' => [ 'lib' ],

    'PM_FILTER' => '$(PREPROCESS) -Mconditional -Mvars -DVERSION="$(VERSION)" -DPREFIX="$(I_PREFIX)"',

    'macro' => {
        DATAFILES => $datafiles,
    },

    # be quite explicit about this; afaik CPAN.pm is sensible using this
    'PREREQ_PM' => {
        'File::Spec'    => 0.8,           # older versions lack some routines we need
        'File::Copy'    => 2.02,          # this version is shipped with 5.005_03, the oldest version known to work
        'Pod::Usage'    => 1.10,          # all versions prior to this do seem to be buggy
        'HTML::Parser'  => 3.24,          # the HTML code is based on this parser
        'Text::Wrap'    => 98.112902,     # this version is shipped with 5.005_03, the oldest version known to work
        'Sys::Hostname' => 0,
        'Time::Local'   => 0,
        'Errno'         => 0,
    },

    'dist' => {
        COMPRESS => 'gzip -9f',
        SUFFIX => 'gz',
        DIST_DEFAULT => 'tardist'
    },

    'clean' => { FILES => join(' ' =>
        'doc', 'pod2htm*',
        'spamassassin', 'sa-learn',
        'spamd/spamd', 'spamd/spamc$(EXE_EXT)',
        'spamd/libspamc.so', 'spamd/libsslspamc.so',
        'spamd/*.o', 'spamd/*.obj',
        'spamd/binaries.mk', 'spamd/config.h', 'spamd/config.status',
        'spamd/config.cache', 'spamd/config.log', 'spamd/autom4te.cache',
        'qmail/qmail-spamc',
        't/do_net', 't/log',
      )
    },

    'AUTHOR'   => 'Justin Mason <jm@jmason.org>',
    'ABSTRACT' => 'identify spam mail using text analysis',

    # We have only this Makefile.PL and this option keeps MakeMaker from
    # asking all questions twice after a 'make dist*'.
    'NORECURS' => 1,

    # Don't add META.yml to the MANIFEST for god's sake!
    'NO_META' => 1,
);
# That META.yml stuff was introduced with Perl 6.06_03, see
# <http://archive.develooper.com/makemaker@perl.org/msg00922.html>
# <http://archive.develooper.com/makemaker@perl.org/msg00984.html>
delete $makefile{'NO_META'} if $mm_version < 6.06_03;


if (bool($opt{'__cruft'}, 0) and not bool($opt{'ignore_cruft'}, 0)) {
  my $error = <<OLD_CRUFT;

    ***********************************************************************
    You attempted to use one of the following unsupported variables:
      INST_PREFIX
      INST_SITELIB
      INST_SYSCONFDIR
      DEF_RULES_DIR
      LOCAL_RULES_DIR
    Please read INSTALL and PACKAGING for new usage instructions.

    Thanks and sorry for any inconvenience.
    ***********************************************************************

OLD_CRUFT
  $error =~ s/^ {4}//gm;
  die $error;
}

if ($mm_needs_destdir) {
  my $error = <<DESTDIR_HACK;

    ***********************************************************************
    ExtUtils::MakeMaker ${mm_version} doesn't include support for DESTDIR,
    so if you want to be on the safe side, you might want to upgrade your
    ExtUtils::MakeMaker to version 6.11 or later. It is available via CPAN.

    You can use either the CPAN shell or go to
      <http://search.cpan.org/search?module=ExtUtils::MakeMaker>
    to get an up-to-date version.

    This should only be necessary if you are creating binary packages.
    ***********************************************************************

DESTDIR_HACK
  $error =~ s/^ {4}//gm;
  warn $error;
}
elsif ($opt{'destdir'} and !$mm_has_good_destdir) {
  my $error = <<DESTDIR_BUG;

    ***********************************************************************
    ExtUtils::MakeMaker ${mm_version} contains bugs that may cause problems
    in the \"make\" process.  It is recommended that you upgrade
    ExtUtils::MakeMaker to version 6.11 or later. It is available via CPAN.

    You can use either the CPAN shell or go to
      <http://search.cpan.org/search?module=ExtUtils::MakeMaker>
    to get an up-to-date version.

    This should only be necessary if you are creating binary packages.
    ***********************************************************************

DESTDIR_BUG
  $error =~ s/^ {4}//gm;
  warn $error;
}


# All the $(*MAN1*) stuff is empty/zero if Perl was Configured with -Dman1dir=none
unless($Config{installman1dir}) {
  delete $makefile{MAN1PODS};
}


# Windows platforms need some adjustments
if (RUNNING_ON_WINDOWS) {
  # Don't build spamd
  delete $makefile{EXE_FILES}['spamd/spamd'];
  # And require Net::DNS v0.44
  #$makefile{PREREQ_PM}{Net::DNS} = 0.44;
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

if (!defined $opt{'run_net_tests'}) {
  $opt{'run_net_tests'} = prompt(
    "Run network tests (these may fail due to network problems)? (y/n)",
    'n');
  print "\n";
}
$opt{'run_net_tests'} = bool($opt{'run_net_tests'});
if ($opt{'run_net_tests'}) {
  open(FLAG, "> t/do_net");
  close(FLAG);
}
else {
  unlink("t/do_net");
}
$makefile{'macro'}{'RUN_NET_TESTS'} = yesno($opt{'run_net_tests'});


# Now dump the Makefile
WriteMakefile(%makefile);
print "Makefile written by ExtUtils::MakeMaker ${mm_version}\n";

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
  my $MUST_NOT_HAPPEN = "THIS MUST NOT HAPPEN. PLEASE REPORT A BUG VIA <http://bugzilla.spamassassin.org>";
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
sub repository {
  my($repository) = (@_);

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

# This routine determines the value of the app given in PERL_BIN.
#
# There are no parameters.
#
# If PERL_VERSION wasn't set at the command line, it will try to call
# the app given in PERL_BIN and ask it for its version. If that doesn't
# work for some reason, it will use the version of the current Perl
# interpreter.
sub _set_macro_PERL_VERSION {

  return if get_macro('PERL_VERSION');

  my($perl, $ver);

  #
  $perl = get_expanded_macro('PERL_BIN');
  if (-x $perl) {
    $ver = qx{$perl -V:version};
    $ver =~ s/^version='([0-9.]+).*$/$1/s;
  }

  $ver = $] unless $ver;

  set_macro('PERL_VERSION', float_to_version($ver));
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
  set_macro('PREPROCESS', join(' ', macro_ref('PERL'), qq{build/preprocessor}));
}

# This routine sets the value for CONFIGURE (spamc only).
#
# There are no parameters.
#
# If CONFIGURE wasn't set at the command line, it chooses our default
# perl-wrapped configure.
sub _set_macro_CONFIGURE {

  return if get_macro('CONFIGURE');
  set_macro('CONFIGURE', join(' ', macro_ref('PERL'), qq{build/configure}));
}





# Override the libscan routine so it skips SVN/CVS stuff and some common
# patch/backup extensions.
sub MY::libscan {
  my $self = shift;
  my($path) = @_;
  init_MY_globals($self);

  return q{} if $path =~ m{
                  (^|/)(CVS|\.svn)(/|$)|
                  [/.](orig|old|rej|r\d+|diff|patch|bak|backup|mine|my)$
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

    # Now do the DESTDIR hack, if necessary.
    next if !$mm_needs_destdir;
    # Write the correct path to perllocal.pod
    next if /installed into/;

    # Replace all other $(INSTALL*) vars (except $(INSTALLDIRS) of course)
    # with their $(DESTINSTALL*) counterparts
    s/\Q$(\E(INSTALL(?!DIRS)${MACRO_RE})\Q)\E/\$(DEST$1)/g;
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

    if (line_has_macro_def($line, 'MM_VERSION')) {
      # These macros are just for debugging purposes.
      $line = join("\n", $line,
         macro_def(MM_HAS_DESTDIR      => ::yesno($mm_has_destdir)),
         macro_def(MM_HAS_GOOD_DESTDIR => ::yesno($mm_has_good_destdir)),
         macro_def(MM_KNOWS_DESTDIR    => ::yesno($mm_knows_destdir)),
         macro_def(MM_NEEDS_DESTDIR    => ::yesno($mm_needs_destdir)),
       );
    }

    # Add DESTDIR support if necessary
    if ($mm_needs_destdir) {
      if (line_has_macro_def($line, 'INSTALLDIRS')) {
        $line .= "\n" . macro_def('DESTDIR');
      }
      elsif (line_has_macro_def($line, qr/INSTALL${MACRO_RE}/)) {
        my $macro = get_macro_name_from_line($line);
        $line .= "\n" . macro_def('DEST' . $macro,
                          macro_ref('DESTDIR') . macro_ref($macro));
      }
    }
  }
  push(@code, qq{});

  # Add some additional target dirs
  {
    set_macro('SYSCONFDIR', "") unless get_macro('SYSCONFDIR');

    # Determine the correct settings for each repository...
    foreach my $r (@REPOSITORIES) {
      _set_macro_SYSCONFDIR($r);
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

    foreach my $m (qw(DATA CONF)) {
      foreach my $r (@REPOSITORIES) {
        my $macro = 'INSTALL' . repository($r) . $m;
        # The INSTALL* macros.
        push(@code, macro_def($macro));
        # The DESTINSTALL* macros.
        push(@code, macro_def('DEST' . $macro,
                      macro_ref('DESTDIR') . macro_ref($macro)))
          if $mm_has_destdir;
      }
    }
  }

  # Set the PERL_* stuff
  {
    _set_macro_PERL_BIN;
    _set_macro_PERL_VERSION;
    _set_macro_PERL_WARN;
    _set_macro_PERL_TAINT;

    # Add it to the Makefile.
    push(@code, qq{});
    push(@code, qq{# Some details about our Perl});
    foreach my $m (qw(BIN VERSION WARN TAINT)) {
      push(@code, macro_def('PERL_' . $m));
    }
  }

  # Set the preprocessor and configure scripts
  {
    _set_macro_PREPROCESS;
    _set_macro_CONFIGURE;

    # Add it to the Makefile.
    push(@code, qq{});
    push(@code, macro_def('PREPROCESS'));
    push(@code, macro_def('CONFIGURE'));
  }

  # Set some additional helper/shortcut macros.
  {
    my($repository);
    $repository = uc($SELF->{INSTALLDIRS}) || 'SITE';

    foreach my $macro (qw(PREFIX SYSCONFDIR)) {
      push(@code, macro_def('I_' . $macro,
                    macro_ref($repository . $macro)));
    }
    foreach my $macro (qw(DATA CONF LIB)) {
      push(@code, macro_def('I_' . $macro . 'DIR',
                    macro_ref('INSTALL' . repository($repository) . $macro)));

      if ($mm_has_destdir) {
        push(@code, macro_def('B_' . $macro . 'DIR',
                      macro_ref('DESTINSTALL' . repository($repository) . $macro)));
      } else {
        push(@code, macro_def('B_' . $macro . 'DIR',
                      macro_ref('I_' . $macro . 'DIR')));
      }
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
		  -DINSTALLSITELIB="$(I_LIBDIR)" \
		  -DCONTACT_ADDRESS="$(CONTACT_ADDRESS)"

FIXBANG		= -Msharpbang \
		  -DPERL_BIN="$(PERL_BIN)" \
		  -DPERL_WARN="$(PERL_WARN)" \
		  -DPERL_TAINT="$(PERL_TAINT)"

SPAMC_SOURCES	= spamd/spamc.c spamd/libspamc.c spamd/utils.c qmail/qmail-spamc.c


spamassassin: spamassassin.raw
	$(PREPROCESS) $(FIXBYTES) $(FIXVARS) $(FIXBANG) -m$(PERM_RWX) -i$? -o$@

sa-learn: sa-learn.raw
	$(PREPROCESS) $(FIXBYTES) $(FIXVARS) $(FIXBANG) -m$(PERM_RWX) -i$? -o$@


spamd/binaries.mk:
	$(CONFIGURE) --srcdir="spamd" --prefix="$(I_PREFIX)" --sysconfdir="$(I_SYSCONFDIR)" --datadir="$(I_DATADIR)" --enable-ssl="$(ENABLE_SSL)"

spamd/spamd: spamd/spamd.raw
	$(PREPROCESS) $(FIXBYTES) $(FIXVARS) $(FIXBANG) -m$(PERM_RWX) -i$? -o$@

spamd/libspamc.so: spamd/binaries.mk $(SPAMC_SOURCES)
	$(MAKE) -f spamd/binaries.mk $@

spamd/spamc$(EXE_EXT): spamd/binaries.mk $(SPAMC_SOURCES)
	$(MAKE) -f spamd/binaries.mk $@

spamd/libsslspamc.so: spamd/binaries.mk $(SPAMC_SOURCES)
	$(MAKE) -f spamd/binaries.mk $@

qmail/qmail-spamc: spamd/binaries.mk $(SPAMC_SOURCES)
	$(MAKE) -f spamd/binaries.mk $@


conf__install:
	-$(MKPATH) $(B_CONFDIR)
	$(PERL) -MFile::Spec -MFile::Copy \
	  -e "copy(q{rules/local.cf}, q{$(B_CONFDIR)/local.cf}) unless -f q{$(B_CONFDIR)/local.cf};"

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
  EOD

  clean_MY_globals($self);
  return $code;
}
