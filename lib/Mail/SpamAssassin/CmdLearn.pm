package Mail::SpamAssassin::CmdLearn;

use strict;
eval "use bytes";

use Mail::SpamAssassin;
use Mail::SpamAssassin::ArchiveIterator;
use Mail::SpamAssassin::NoMailAudit;
use Mail::SpamAssassin::PerMsgLearner;
use Getopt::Long;
use Pod::Usage;

use vars qw($spamtest %opt $isspam $forget $messagecount $messagelimit
	$rebuildonly $learnprob
	);

###########################################################################

sub cmdline_run {
  my ($opts) = shift;

  $isspam = $opts->{isspam};
  $forget = $opts->{forget};
  $rebuildonly = $opts->{rebuildonly};

  %opt = ();

  Getopt::Long::Configure(qw(bundling no_getopt_compat
                         no_auto_abbrev no_ignore_case));

  GetOptions(
             'whitelist-factory=s'              => \$opt{'whitelist-factory'},
             'config-file|C=s'                  => \$opt{'config-file'},
             'prefs-file|p=s'                   => \$opt{'prefs-file'},

             # arguments from mass-check.  don't add more unless you're
             # sure they're required!
             'folders|f=s'                      => \$opt{'folders'},
             'mh'                               => \$opt{'mh'},
             'single|s'                         => \$opt{'single'},
             'showdots'                         => \$opt{'showdots'},
	     'no-rebuild'			=> \$opt{'norebuild'},
	     'force-expire'			=> \$opt{'force-expire'},

             'stopafter'                        => \$opt{'stopafter'},
	     'learnprob=f'			=> \$opt{'learnprob'},
	     'randseed=i'			=> \$opt{'randseed'},

             'auto-whitelist|a'                 => \$opt{'auto-whitelist'},
             'bias-scores|b'                    => \$opt{'bias-scores'},

             'debug-level|D'                    => \$opt{'debug-level'},
             'version|V'                        => \$opt{'version'},
             'help|h|?'                         => \$opt{'help'},
             #'<>'                               => \&add_folder,
  ) or usage(0, "Unknown option!");

  if (defined $opt{'help'}) { usage(0, "For more information read the manual page"); }
  if (defined $opt{'version'}) {
    print "SpamAssassin version " . Mail::SpamAssassin::Version() . "\n";
    exit 0;
  }

  # create the tester factory
  $spamtest = new Mail::SpamAssassin ({
    rules_filename	=> $opt{'config-file'},
    userprefs_filename  => $opt{'prefs-file'},
    debug               => defined($opt{'debug-level'}),
    local_tests_only    => 1,
    dont_copy_prefs     => 1,
    PREFIX              => $main::PREFIX,
    DEF_RULES_DIR       => $main::DEF_RULES_DIR,
    LOCAL_RULES_DIR     => $main::LOCAL_RULES_DIR,
  });

  $spamtest->init_learner({
      use_whitelist     => $opt{'auto-whitelist'},
      bias_scores       => $opt{'bias-scores'},
      force_expire	=> $opt{'force-expire'},
  });

  if ($opts->{rebuildonly}) {
    $spamtest->init (1);
    $spamtest->rebuild_learner_caches();
    $spamtest->finish_learner();
    return 0;
  }

  $messagelimit = $opt{'stopafter'};
  $learnprob = $opt{'learnprob'};

  if (defined $opt{'randseed'}) {
    srand ($opt{'randseed'});
  }

  # run this lot in an eval block, so we can catch die's and clear
  # up the dbs.
  eval {
    $spamtest->init (1);

    $SIG{INT} = \&killed;
    $SIG{TERM} = \&killed;

    my $iter = new Mail::SpamAssassin::ArchiveIterator ({
	    'opt_mh' => $opt{mh},
	    'opt_single' => $opt{single},
      });

    my @targets = @ARGV;
    if ($opt{folders}) {
      open (F, $opt{folders}) || die $!;
      push (@targets, map { chomp; $_ } <F>);
      close (F);
    }

    $iter->set_function (\&wanted);
    $messagecount = 0;

    eval {
      $iter->run (@targets);
    };
    if ($@) { die $@ unless ($@ =~ /HITLIMIT/); }

    print STDERR "\n" if ($opt{showdots});
    if (defined $learnprob) {
      warn "Learned from $messagecount messages.\n";
    }

    if (!$opt{norebuild}) {
      $spamtest->rebuild_learner_caches();
    }
  };

  if ($@) {
    my $failure = $@;
    $spamtest->finish_learner();
    die $failure;
  }

  $spamtest->finish_learner();
  return 0;
}

sub killed {
  $spamtest->finish_learner();
  die "interrupted";
}

###########################################################################

sub wanted {
  my ($id, $dataref) = @_;

  if (defined($learnprob)) {
    if (int (rand (1/$learnprob)) != 0) {
      print STDERR '_' if ($opt{showdots});
      return;
    }
  }

  if (defined($messagelimit) && $messagecount > $messagelimit)
					{ die 'HITLIMIT'; }
  $messagecount++;

  my $ma = Mail::SpamAssassin::NoMailAudit->new ('data' => $dataref);

  if ($ma->get ("X-Spam-Status")) {
    my $newtext = $spamtest->remove_spamassassin_markup($ma);
    my @newtext = split (/^/m, $newtext);
    $dataref = \@newtext;
    $ma = Mail::SpamAssassin::NoMailAudit->new ('data' => $dataref);
  }

  $ma->{noexit} = 1;
  my $status = $spamtest->learn ($ma, $id, $isspam, $forget);

  $status->finish();
  undef $ma;            # clean 'em up
  undef $status;

  print STDERR '.' if ($opt{showdots});
}

###########################################################################

sub usage {
    my ($verbose, $message) = @_;
    my $ver = Mail::SpamAssassin::Version();
    print "SpamAssassin version $ver\n";
    pod2usage(-verbose => $verbose, -message => $message, -exitval => 64);
}

1;
