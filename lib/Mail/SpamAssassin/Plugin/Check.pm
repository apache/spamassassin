=head1 NAME

Mail::SpamAssassin::Plugin::Check

=head1 SYNOPSIS

loadplugin Mail::SpamAssassin::Plugin::Check

=head1 DESCRIPTION

This plugin provides the primary message check functionality.

=cut

package Mail::SpamAssassin::Plugin::Check;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Util;
use Mail::SpamAssassin::Constants qw(:sa);

use strict;
use warnings;

use vars qw(@ISA @TEMPORARY_METHODS);
@ISA = qw(Mail::SpamAssassin::Plugin);

# methods defined by the compiled ruleset; deleted in finish_tests() 
@TEMPORARY_METHODS = (); 

# constructor
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  return $self;
}

###########################################################################

sub check_main {
  my ($self, $args) = @_;

  my $pms = $args->{permsgstatus};

  # bug 4353:
  # Do this before the RBL tests are kicked off.  The metadata parsing
  # will figure out the (un)trusted relays and such, which are used in the
  # rbl calls.
  $pms->extract_message_metadata();

  # Here, we launch all the DNS RBL queries and let them run while we
  # inspect the message
  $self->run_rbl_eval_tests($pms);
  my $needs_dnsbl_harvest_p = 1; # harvest needs to be run

  my $decoded = $pms->get_decoded_stripped_body_text_array();
  my $bodytext = $pms->get_decoded_body_text_array();
  my $fulltext = $pms->{msg}->get_pristine();

  my @uris = $pms->get_uri_list();

  foreach my $priority (sort { $a <=> $b } keys %{$pms->{conf}->{priorities}}) {
    # no need to run if there are no priorities at this level.  This can
    # happen in Conf.pm when we switch a rules from one priority to another
    next unless ($pms->{conf}->{priorities}->{$priority} > 0);

    # if shortcircuiting is hit, we skip all other priorities...
    last if $self->{main}->call_plugins("have_shortcircuited", { permsgstatus => $pms });

    dbg("check: running tests for priority: $priority");

    # only harvest the dnsbl queries once priority HARVEST_DNSBL_PRIORITY
    # has been reached and then only run once
    if ($priority >= HARVEST_DNSBL_PRIORITY
        && $needs_dnsbl_harvest_p
        && !$self->{main}->call_plugins("have_shortcircuited",
                                        { permsgstatus => $pms }))
    {
      # harvest the DNS results
      $pms->harvest_dnsbl_queries();
      $needs_dnsbl_harvest_p = 0;

      # finish the DNS results
      $pms->rbl_finish();
      $self->{main}->call_plugins("check_post_dnsbl", { permsgstatus => $pms });
      $pms->{resolver}->finish_socket() if $pms->{resolver};
    }

    # allow other, plugin-defined rule types to be called here
    $self->{main}->call_plugins ("check_rules_at_priority",
        { permsgstatus => $pms, priority => $priority, checkobj => $self });

    # do head tests
    $self->do_head_tests($pms, $priority);
    $self->do_head_eval_tests($pms, $priority);

    $self->do_body_tests($pms, $priority, $decoded);
    $self->do_uri_tests($pms, $priority, @uris);
    $self->do_body_eval_tests($pms, $priority, $decoded);
  
    $self->do_rawbody_tests($pms, $priority, $bodytext);
    $self->do_rawbody_eval_tests($pms, $priority, $bodytext);
  
    $self->do_full_tests($pms, $priority, \$fulltext);
    $self->do_full_eval_tests($pms, $priority, \$fulltext);

    $self->do_meta_tests($pms, $priority);

    # we may need to call this more often than once through the loop, but
    # it needs to be done at least once, either at the beginning or the end.
    $self->{main}->call_plugins ("check_tick", { permsgstatus => $pms });
  }

  # sanity check, it is possible that no rules >= HARVEST_DNSBL_PRIORITY ran so the harvest
  # may not have run yet.  Check, and if so, go ahead and harvest here.
  if ($needs_dnsbl_harvest_p) {
    if (!$self->{main}->call_plugins("have_shortcircuited",
                                        { permsgstatus => $pms }))
    {
      # harvest the DNS results
      $pms->harvest_dnsbl_queries();
    }

    # finish the DNS results
    $pms->rbl_finish();
    $self->{main}->call_plugins ("check_post_dnsbl", { permsgstatus => $pms });
    $pms->{resolver}->finish_socket() if $pms->{resolver};
  }

  # finished running rules
  delete $pms->{current_rule_name};
  undef $decoded;
  undef $bodytext;
  undef $fulltext;

  # auto-learning
  $pms->learn();
  $self->{main}->call_plugins ("check_post_learn", { permsgstatus => $pms });

  return 1;
}

sub finish_tests {
  my ($self, $params) = @_;

  foreach my $method (@TEMPORARY_METHODS) {
    undef &{$method};
  }
  @TEMPORARY_METHODS = ();      # clear for next time
}

###########################################################################

sub run_rbl_eval_tests {
  my ($self, $pms) = @_;
  my ($rulename, $pat, @args);

  # XXX - possible speed up, moving this check out of the subroutine into Check->new()
  if ($self->{main}->{local_tests_only}) {
    dbg("rules: local tests only, ignoring RBL eval");
    return 0;
  }

  while (my ($rulename, $test) = each %{$pms->{conf}->{rbl_evals}}) {
    my $score = $pms->{conf}->{scores}->{$rulename};
    next unless $score;

    $pms->{test_log_msgs} = ();        # clear test state

    my ($function, @args) = @{$test};

    my $result;
    eval {
       $result = $pms->$function($rulename, @args);
    };

    if ($@) {
      warn "rules: failed to run $rulename RBL test, skipping:\n" . "\t($@)\n";
      $pms->{rule_errors}++;
      next;
    }
  }
}

###########################################################################

sub run_generic_tests {
  my ($self, $pms, $priority, %opts) = @_;

  return if $self->{main}->call_plugins("have_shortcircuited",
                                        { permsgstatus => $pms });

  my $ruletype = $opts{type};
  dbg("rules: running ".$ruletype." tests; score so far=".$pms->{score});
  $pms->{test_log_msgs} = ();        # clear test state

  my $conf = $pms->{conf};
  my $doing_user_rules = $conf->{user_rules_to_compile}->{$opts{consttype}};

  # clean up priority value so it can be used in a subroutine name
  my $clean_priority;
  ($clean_priority = $priority) =~ s/-/neg/;
  my $package_name = __PACKAGE__;
  my $methodname = $package_name."::_".$ruletype."_tests_".$clean_priority;

  if (defined &{$methodname} && !$doing_user_rules) {
    no strict "refs";
run_compiled_method:
    $methodname->($pms, @{$opts{args}});
    use strict "refs";
    return;
  }

  # build up the eval string...
  $self->{evalstr} = $self->start_rules_plugin_code($ruletype, $priority);
  $self->{evalstr2} = '';

  # use %nopts for named parameter-passing; it's more friendly to future-proof
  # subclassing, since new parameters can be added without breaking third-party
  # subclassed implementations of this plugin.
  my %nopts = (
    ruletype => $ruletype,
    doing_user_rules => $doing_user_rules,
    priority => $priority,
    clean_priority => $clean_priority
  );

  if (defined $opts{pre_loop_body}) {
    $opts{pre_loop_body}->($self, $pms, $conf, %nopts);
  }
  while (my($rulename, $test) = each %{$opts{testhash}->{$priority}}) {
    $opts{loop_body}->($self, $pms, $conf, $rulename, $test, %nopts);
  }
  if (defined $opts{post_loop_body}) {
    $opts{post_loop_body}->($self, $pms, $conf, %nopts);
  }

  # clear out a previous version of this fn
  undef &{$methodname};
  $self->free_ruleset_source($pms, $ruletype, $priority);

  my $evalstr = $self->{evalstr};

  # generate the loop that goes through each line...
  $evalstr = <<"EOT";
  {
    package $package_name;

    $self->{evalstr2}

    sub $methodname {
      my \$self = shift;
      $evalstr;
    }

    1;
  }
EOT

  delete $self->{evalstr};
  delete $self->{evalstr2}; # free up some RAM before we eval()

  ## dbg ("rules: eval code to compile: $evalstr");
  eval $evalstr;
  if ($@) {
    warn("rules: failed to compile $ruletype tests, skipping:\n\t($@)\n");
    $pms->{rule_errors}++;
  }
  else {
    dbg("rules: compiled ".$ruletype." tests");
    goto run_compiled_method;
  }
}

sub add_evalstr {
  my ($self, $str) = @_;
  $self->{evalstr} .= $str;
}

sub add_evalstr2 {
  my ($self, $str) = @_;
  $self->{evalstr2} .= $str;
}

sub add_temporary_method {
  my ($self, $methodname, $methodbody) = @_;
  $self->add_evalstr2 (' sub '.$methodname.' { '.$methodbody.' } ');
  push (@TEMPORARY_METHODS, $methodname);
}

###########################################################################

sub do_meta_tests {
  my ($self, $pms, $priority) = @_;
  my (%rule_deps, %meta, $rulename);

  $self->run_generic_tests ($pms, $priority,
    consttype => $Mail::SpamAssassin::Conf::TYPE_META_TESTS,
    type => 'meta',
    testhash => $pms->{conf}->{meta_tests},
    args => [ ],
    loop_body => sub
  {
    my ($self, $pms, $conf, $rulename, $rule, %opts) = @_;
    my $token;

    # Lex the rule into tokens using a rather simple RE method ...
    my $lexer = ARITH_EXPRESSION_LEXER;
    my @tokens = ($rule =~ m/$lexer/g);

    # Set the rule blank to start
    $meta{$rulename} = "";

    # List dependencies that are meta tests in the same priority band
    $rule_deps{$rulename} = [ ];

    # Go through each token in the meta rule
    foreach $token (@tokens) {

      # Numbers can't be rule names
      if ($token =~ /^(?:\W+|[+-]?\d+(?:\.\d+)?)$/) {
        $meta{$rulename} .= "$token ";
      }
      else {
        # the " || 0" formulation is to avoid "use of uninitialized value"
        # warnings; this is better than adding a 0 to a hash for every
        # rule referred to in a meta...
        $meta{$rulename} .= "(\$h->{'$token'} || 0) ";
      
        if (!exists $conf->{scores}->{$token}) {
          dbg("rules: meta test $rulename has undefined dependency '$token'");
        }
        elsif ($conf->{scores}->{$token} == 0) {
          # bug 5040: net rules in a non-net scoreset
          # there are some cases where this is expected; don't warn
          # in those cases.
          unless ((($conf->get_score_set()) & 1) == 0 &&
              ($conf->{tflags}->{$token}||'') =~ /\bnet\b/)
          {
            info("rules: meta test $rulename has dependency '$token' with a zero score");
          }
        }

        # If the token is another meta rule, add it as a dependency
        push (@{ $rule_deps{$rulename} }, $token)
          if (exists $conf->{meta_tests}->{$opts{priority}}->{$token});
      }
    }
  },
    pre_loop_body => sub
  {
    my ($self, $pms, $conf, %opts) = @_;
    $self->add_evalstr ('
      my $r;
      my $h = $self->{tests_already_hit};
    ');
  },
    post_loop_body => sub
  {
    my ($self, $pms, $conf, %opts) = @_;

    # Sort by length of dependencies list.  It's more likely we'll get
    # the dependencies worked out this way.
    my @metas = sort { @{ $rule_deps{$a} } <=> @{ $rule_deps{$b} } }
                keys %{$conf->{meta_tests}->{$opts{priority}}};

    my $count;
    my $tflags = $conf->{tflags};

    # Now go ahead and setup the eval string
    do {
      $count = $#metas;
      my %metas = map { $_ => 1 } @metas; # keep a small cache for fast lookups

      # Go through each meta rule we haven't done yet
      for (my $i = 0 ; $i <= $#metas ; $i++) {

        # If we depend on meta rules that haven't run yet, skip it
        next if (grep( $metas{$_}, @{ $rule_deps{ $metas[$i] } }));

        # If we depend on network tests, call ensure_rules_are_complete()
        # to block until they are
        my $alldeps = join ' ', grep {
                ($tflags->{$_}||'') =~ /\bnet\b/
              } split (' ', $conf->{meta_dependencies}->{ $metas[$i] } );

        if ($alldeps ne '') {
          $self->add_evalstr ('
            $self->ensure_rules_are_complete(q{'.$metas[$i].'}, qw{'.$alldeps.'});
          ');
        }

        # Add this meta rule to the eval line
        $self->add_evalstr ('
          $r = '.$meta{$metas[$i]}.';
          if ($r) { $self->got_hit(q#'.$metas[$i].'#, "", ruletype => "meta", value => $r); }
        ');

        splice @metas, $i--, 1;    # remove this rule from our list
      }
    } while ($#metas != $count && $#metas > -1); # run until we can't go anymore

    # If there are any rules left, we can't solve the dependencies so complain
    my %metas = map { $_ => 1 } @metas; # keep a small cache for fast lookups
    foreach $rulename (@metas) {
      $pms->{rule_errors}++; # flag to --lint that there was an error ...
      my $msg =
          "rules: excluding meta test $rulename, unsolved meta dependencies: " .
              join(", ", grep($metas{$_}, @{ $rule_deps{$rulename} }));
      if ($self->{main}->{lint_rules}) {
        warn $msg."\n";
      }
      else {
        info($msg);
      }
    }
  }
  );
}

###########################################################################

sub do_head_tests {
  my ($self, $pms, $priority) = @_;
  # hash to hold the rules, "header\tdefault value" => rulename
  my %ordered = ();
  my %testcode = ();

  $self->run_generic_tests ($pms, $priority,
    consttype => $Mail::SpamAssassin::Conf::TYPE_HEAD_TESTS,
    type => 'head',
    testhash => $pms->{conf}->{head_tests},
    args => [ ],
    loop_body => sub
  {
    my ($self, $pms, $conf, $rulename, $rule, %opts) = @_;
    my $def = '';
    my ($hdrname, $testtype, $pat) =
        $rule =~ /^\s*(\S+)\s*(\=|\!)\~\s*(\S.*?\S)\s*$/;

    if (!defined $pat) {
      warn "rules: invalid rule: $rulename\n";
      $pms->{rule_errors}++;
      next;
    }

    if ($pat =~ s/\s+\[if-unset:\s+(.+)\]\s*$//) { $def = $1; }

    $hdrname =~ s/#/[HASH]/g;                # avoid probs with eval below
    $def =~ s/#/[HASH]/g;

    push(@{$ordered{"$hdrname\t$def"}}, $rulename);

    next if ($opts{doing_user_rules} &&
            !$self->is_user_rule_sub($rulename.'_head_test'));

    # caller can set this member of the Mail::SpamAssassin object to
    # override this; useful for profiling rule runtimes, although I think
    # the HitFreqsRuleTiming.pm plugin is probably better nowadays anyway
      if ($self->{main}->{use_rule_subs}) {
      $self->add_temporary_method ($rulename.'_head_test', '{
          my($self,$text) = @_;
          '.$self->hash_line_for_rule($pms, $rulename).'
	    while ($text '.$testtype.'~ '.$pat.'g) {
            $self->got_hit(q#'.$rulename.'#, "", ruletype => "header");
            '. $self->hit_rule_plugin_code($pms, $rulename, "header", "last") . '
            }
        }');
    }
    else {
      # store for use below
      $testcode{$rulename} = $testtype.'~ '.$pat;
    }
  },
    pre_loop_body => sub
  {
    my ($self, $pms, $conf, %opts) = @_;
    $self->add_evalstr ('
      my $hval;
    ');
  },
    post_loop_body => sub
  {
    my ($self, $pms, $conf, %opts) = @_;
    # setup the function to run the rules
    while(my($k,$v) = each %ordered) {
      my($hdrname, $def) = split(/\t/, $k, 2);
      $self->add_evalstr ('
        $hval = $self->get(q#'.$hdrname.'#, q#'.$def.'#);
      ');
      foreach my $rulename (@{$v}) {
        if ($self->{main}->{use_rule_subs}) {
          $self->add_evalstr ('
            if ($scoresptr->{q#'.$rulename.'#}) {
              '.$rulename.'_head_test($self, $hval);
              '.$self->ran_rule_plugin_code($rulename, "header").'
            }
          ');
        }
        else {
          my $testcode = $testcode{$rulename};

          my $posline = '';
          my $ifwhile = 'if';
          my $hitdone = '';
          my $matchg = '';
          if (($conf->{tflags}->{$rulename}||'') =~ /\bmultiple\b/)
          {
            $posline = 'pos $hval = 0;';
            $ifwhile = 'while';
            $hitdone = 'last';
            $matchg = 'g';
          }

          $self->add_evalstr ('
          if ($scoresptr->{q#'.$rulename.'#}) {
            '.$posline.'
            '.$self->hash_line_for_rule($pms, $rulename).'
            '.$ifwhile.' ($hval '.$testcode.$matchg.') {
              $self->got_hit(q#'.$rulename.'#, "", ruletype => "header");
              '.$self->hit_rule_plugin_code($pms, $rulename, "header", $hitdone).'
            }
            '.$self->ran_rule_plugin_code($rulename, "header").'
          }
          ');
        }
      }
    }
  }
  );
}

###########################################################################

sub do_body_tests {
  my ($self, $pms, $priority, $textary) = @_;
  my $loopid = 0;

  $self->run_generic_tests ($pms, $priority,
    consttype => $Mail::SpamAssassin::Conf::TYPE_BODY_TESTS,
    type => 'body',
    testhash => $pms->{conf}->{body_tests},
    args => [ @$textary ],
    loop_body => sub
  {
    my ($self, $pms, $conf, $rulename, $pat, %opts) = @_;
    my $sub;
    if (($conf->{tflags}->{$rulename}||'') =~ /\bmultiple\b/)
    {
      # support multiple matches
      $loopid++;
      $sub = '
      body_'.$loopid.': foreach my $l (@_) {
        pos $l = 0;
        '.$self->hash_line_for_rule($pms, $rulename).'
        while ($l =~ '.$pat.'g) { 
          $self->got_hit(q{'.$rulename.'}, "BODY: ", ruletype => "body"); 
          '. $self->hit_rule_plugin_code($pms, $rulename, 'body',
					 "last body_".$loopid) . '
        }
      }
      ';
    }
    else {
      # omitting the "pos" call, "body_loopid" label, use of while()
      # instead of if() etc., shaves off 8 perl OPs.
      $sub = '
      foreach my $l (@_) {
        '.$self->hash_line_for_rule($pms, $rulename).'
        if ($l =~ '.$pat.') { 
          $self->got_hit(q{'.$rulename.'}, "BODY: ", ruletype => "body"); 
          '. $self->hit_rule_plugin_code($pms, $rulename, "body", "last") .'
        }
      }
      ';
    }

    if ($self->{main}->{use_rule_subs}) {
      $self->add_evalstr ('
        if ($scoresptr->{q{'.$rulename.'}}) {
          '.$rulename.'_body_test($self,@_); 
          '.$self->ran_rule_plugin_code($rulename, "body").'
        }
      ');
    }
    else {
      $self->add_evalstr ('
        if ($scoresptr->{q{'.$rulename.'}}) {
          '.$sub.'
          '.$self->ran_rule_plugin_code($rulename, "body").'
        }
      ');
    }

    next if ($opts{doing_user_rules} &&
            !$self->is_user_rule_sub($rulename.'_body_test'));

    if ($self->{main}->{use_rule_subs}) {
      $self->add_temporary_method ($rulename.'_body_test',
        '{ my $self = shift; '.$sub.' }');
    }
  }
  );
}

###########################################################################

sub do_uri_tests {
  my ($self, $pms, $priority, @uris) = @_;
  my $loopid = 0;
  $self->run_generic_tests ($pms, $priority,
    consttype => $Mail::SpamAssassin::Conf::TYPE_URI_TESTS,
    type => 'uri',
    testhash => $pms->{conf}->{uri_tests},
    args => [ @uris ],
    loop_body => sub
  {
    my ($self, $pms, $conf, $rulename, $pat, %opts) = @_;
    my $sub;
    if (($conf->{tflags}->{$rulename}||'') =~ /\bmultiple\b/) {
      $loopid++;
      $sub = '
      uri_'.$loopid.': foreach my $l (@_) {
        pos $l = 0;
        '.$self->hash_line_for_rule($pms, $rulename).'
        while ($l =~ '.$pat.'g) { 
           $self->got_hit(q{'.$rulename.'}, "URI: ", ruletype => "uri");
           '. $self->hit_rule_plugin_code($pms, $rulename, "uri",
					  "last uri_".$loopid) . '
        }
      }
      ';
    } else {
      $sub = '
      foreach my $l (@_) {
        '.$self->hash_line_for_rule($pms, $rulename).'
        if ($l =~ '.$pat.') { 
           $self->got_hit(q{'.$rulename.'}, "URI: ", ruletype => "uri");
           '. $self->hit_rule_plugin_code($pms, $rulename, "uri", "last") .'
        }
      }
      ';
    }

    if ($self->{main}->{use_rule_subs}) {
      $self->add_evalstr ('
        if ($scoresptr->{q{'.$rulename.'}}) {
          '.$rulename.'_uri_test($self, @_);
          '.$self->ran_rule_plugin_code($rulename, "uri").'
        }
      ');
    }
    else {
      $self->add_evalstr ('
        if ($scoresptr->{q{'.$rulename.'}}) {
          '.$sub.'
          '.$self->ran_rule_plugin_code($rulename, "uri").'
        }
      ');
    }

    next if ($opts{doing_user_rules} &&
            !$self->is_user_rule_sub($rulename.'_uri_test'));

    if ($self->{main}->{use_rule_subs}) {
      $self->add_temporary_method ($rulename.'_uri_test',
        '{ my $self = shift; '.$sub.' }');
    }
  }
  );
}

###########################################################################

sub do_rawbody_tests {
  my ($self, $pms, $priority, $textary) = @_;
  my $loopid = 0;
  $self->run_generic_tests ($pms, $priority,
    consttype => $Mail::SpamAssassin::Conf::TYPE_RAWBODY_TESTS,
    type => 'rawbody',
    testhash => $pms->{conf}->{rawbody_tests},
    args => [ @$textary ],
    loop_body => sub
  {
    my ($self, $pms, $conf, $rulename, $pat, %opts) = @_;
    my $sub;
    if (($pms->{conf}->{tflags}->{$rulename}||'') =~ /\bmultiple\b/)
    {
      # support multiple matches
      $loopid++;
      $sub = '
      rawbody_'.$loopid.': foreach my $l (@_) {
        pos $l = 0;
        '.$self->hash_line_for_rule($pms, $rulename).'
        while ($l =~ '.$pat.'g) { 
           $self->got_hit(q{'.$rulename.'}, "RAW: ", ruletype => "rawbody");
           '. $self->hit_rule_plugin_code($pms, $rulename, "rawbody",
					  "last rawbody_".$loopid) . '
        }
      }
      ';
    }
    else {
      $sub = '
      foreach my $l (@_) {
        '.$self->hash_line_for_rule($pms, $rulename).'
        if ($l =~ '.$pat.') { 
           $self->got_hit(q{'.$rulename.'}, "RAW: ", ruletype => "rawbody");
           '. $self->hit_rule_plugin_code($pms, $rulename, "rawbody", "last") . '
        }
      }
      ';
    }

    if ($self->{main}->{use_rule_subs}) {
      $self->add_evalstr ('
        if ($scoresptr->{q{'.$rulename.'}}) {
           '.$rulename.'_rawbody_test($self, @_);
           '.$self->ran_rule_plugin_code($rulename, "rawbody").'
        }
      ');
    }
    else {
      $self->add_evalstr ('
        if ($scoresptr->{q{'.$rulename.'}}) {
          '.$sub.'
          '.$self->ran_rule_plugin_code($rulename, "rawbody").'
        }
      ');
    }

    next if ($opts{doing_user_rules} &&
            !$self->is_user_rule_sub($rulename.'_rawbody_test'));

    if ($self->{main}->{use_rule_subs}) {
      $self->add_temporary_method ($rulename.'_rawbody_test',
        '{ my $self = shift; '.$sub.' }');
    }
  }
  );
}

###########################################################################

sub do_full_tests {
  my ($self, $pms, $priority, $fullmsgref) = @_;
  my $loopid = 0;
  $self->run_generic_tests ($pms, $priority,
    consttype => $Mail::SpamAssassin::Conf::TYPE_FULL_TESTS,
    type => 'full',
    testhash => $pms->{conf}->{full_tests},
    args => [ $fullmsgref ],
    pre_loop_body => sub
  {
    my ($self, $pms, $conf, %opts) = @_;
    $self->add_evalstr ('
      my $fullmsgref = shift;
    ');
  },
                loop_body => sub
  {
    my ($self, $pms, $conf, $rulename, $pat, %opts) = @_;
    $self->add_evalstr ('
      if ($scoresptr->{q{'.$rulename.'}}) {
        pos $$fullmsgref = 0;
        '.$self->hash_line_for_rule($pms, $rulename).'
        while ($$fullmsgref =~ '.$pat.'g) {
          $self->got_hit(q{'.$rulename.'}, "FULL: ", ruletype => "full");
          '. $self->hit_rule_plugin_code($pms, $rulename, "full", "last") . '
        }
        '.$self->ran_rule_plugin_code($rulename, "full").'
      }
    ');
  }
  );
}

###########################################################################

sub do_head_eval_tests {
  my ($self, $pms, $priority) = @_;
  return unless (defined($pms->{conf}->{head_evals}->{$priority}));
  $self->run_eval_tests ($pms, $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS,
			 $pms->{conf}->{head_evals}->{$priority}, '', $priority);
}

sub do_body_eval_tests {
  my ($self, $pms, $priority, $bodystring) = @_;
  return unless (defined($pms->{conf}->{body_evals}->{$priority}));
  $self->run_eval_tests ($pms, $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS,
			 $pms->{conf}->{body_evals}->{$priority}, 'BODY: ',
			 $priority, $bodystring);
}

sub do_rawbody_eval_tests {
  my ($self, $pms, $priority, $bodystring) = @_;
  return unless (defined($pms->{conf}->{rawbody_evals}->{$priority}));
  $self->run_eval_tests ($pms, $Mail::SpamAssassin::Conf::TYPE_RAWBODY_EVALS,
			 $pms->{conf}->{rawbody_evals}->{$priority}, 'RAW: ',
			 $priority, $bodystring);
}

sub do_full_eval_tests {
  my ($self, $pms, $priority, $fullmsgref) = @_;
  return unless (defined($pms->{conf}->{full_evals}->{$priority}));
  $self->run_eval_tests($pms, $Mail::SpamAssassin::Conf::TYPE_FULL_EVALS,
			$pms->{conf}->{full_evals}->{$priority}, '',
			$priority, $fullmsgref);
}

sub run_eval_tests {
  my ($self, $pms, $testtype, $evalhash, $prepend2desc, $priority, @extraevalargs) = @_;
 
  return if $self->{main}->call_plugins("have_shortcircuited",
                                        { permsgstatus => $pms });

  my $conf = $pms->{conf};
  my $doing_user_rules = $conf->{user_rules_to_compile}->{$testtype};

  # clean up priority value so it can be used in a subroutine name 
  my $clean_priority;
  ($clean_priority = $priority) =~ s/-/neg/;

  my $scoreset = $conf->get_score_set();

  my $package_name = __PACKAGE__;

  my $methodname = '_eval_tests'.
    '_type'.$testtype .
      '_pri'.$clean_priority .
	'_set'.$scoreset;

  # Some of the rules are scoreset specific, so we need additional
  # subroutines to handle those
  if (defined &{"${package_name}::${methodname}"}
      && !$doing_user_rules)
  {
    no strict "refs";
    &{"${package_name}::${methodname}"}($pms,@extraevalargs);
    use strict "refs";
    return;
  }

  # look these up once in advance to save repeated lookups in loop below
  my $tflagsref = $conf->{tflags};
  my $eval_pluginsref = $conf->{eval_plugins};
  my $have_start_rules = $self->{main}->have_plugin("start_rules");
  my $have_ran_rule = $self->{main}->have_plugin("ran_rule");

  # the buffer for the evaluated code 
  my $evalstr = q{ };
  $evalstr .= q{ my $function; };
 
  # conditionally include the dbg in the eval str
  my $dbgstr = q{ };
  if (would_log('dbg')) {
    $dbgstr = q{
      dbg("rules: ran eval rule $rulename ======> got hit ($result)");
    };
  }

  while (my ($rulename, $test) = each %{$evalhash})  { 
    if ($tflagsref->{$rulename}) {
      # If the rule is a net rule, and we are in a non-net scoreset, skip it.
      if ($tflagsref->{$rulename} =~ /\bnet\b/) {
        next if (($scoreset & 1) == 0);
      }
      # If the rule is a bayes rule, and we are in a non-bayes scoreset, skip it.
      if ($tflagsref->{$rulename} =~ /\blearn\b/) {
        next if (($scoreset & 2) == 0);
      }
    }
 
    my ($function, $argstr) = ($test,'');
    if ($test =~ s/^([^,]+)(,.*)$//gs) {
      ($function, $argstr) = ($1,$2);
    }

    if (!$function) {
      warn "rules: error: no function defined for $rulename";
      next;
    }
 
    $evalstr .= '
      $rulename = q#'.$rulename.'#;
      $self->{test_log_msgs} = ();
    ';
 
    # only need to set current_rule_name for plugin evals
    if ($eval_pluginsref->{$function}) {
      # let plugins get the name of the rule that is currently being run,
      # and ensure their eval functions exist
      $evalstr .= '

        $self->{current_rule_name} = $rulename;
        $self->register_plugin_eval_glue(q#'.$function.'#);

      ';
    }

    # this stuff is quite slow, and totally superfluous if
    # no plugin is loaded for those hooks
    if ($have_start_rules) {
      # XXX - should we use helper function here?
      $evalstr .= '

        $self->{main}->call_plugins("start_rules", {
                permsgstatus => $self,
                ruletype => "eval",
                priority => '.$priority.'
              });

      ';
    }
 
    $evalstr .= '

      eval {
        $result = $self->' . $function . ' (@extraevalargs '. $argstr .' );
      };
      if ($@) { $self->handle_eval_rule_errors($rulename); }

    ';

    if ($have_ran_rule) {
      # XXX - should we use helper function here?
      $evalstr .= '

        $self->{main}->call_plugins("ran_rule", {
            permsgstatus => $self, ruletype => "eval", rulename => $rulename
          });

      ';
    }

    $evalstr .= '

      if ($result) {
        $self->got_hit($rulename, $prepend2desc, ruletype => "eval", value => $result);
        '.$dbgstr.'
      }

    ';
  }

  # don't free the eval ruleset here -- we need it in the compiled code!

  # nothing done in the loop, that means no rules 
  return unless ($evalstr);
 
  $evalstr = <<"EOT";
{
  package $package_name;

    sub ${methodname} {
      my (\$self, \@extraevalargs) = \@_;

      my \$prepend2desc = q#$prepend2desc#;
      my \$rulename;
      my \$result;

      $evalstr
    }

  1;
}
EOT

  eval $evalstr;

  if ($@) {
    warn "rules: failed to compile eval tests, skipping some: $@\n";
    $self->{rule_errors}++;
  }
  else {
    my $method = "${package_name}::${methodname}";
    push (@TEMPORARY_METHODS, $methodname);
    no strict "refs";
    &{$method}($pms,@extraevalargs);
    use strict "refs";
  }
}

###########################################################################
# Helper Functions

sub hash_line_for_rule {
  my ($self, $pms, $rulename) = @_;
  return "\n".'#line 1 "'.
        $pms->{conf}->{source_file}->{$rulename}.
        ', rule '.$rulename.',"';
}

sub is_user_rule_sub {
  my ($self, $subname) = @_;
  my $package_name = __PACKAGE__;
  return 0 if (eval 'defined &'.$package_name.'::'.$subname);
  1;
}

sub start_rules_plugin_code {
  my ($self, $ruletype, $pri) = @_;

  my $evalstr = '

      # start_rules_plugin_code '.$ruletype.' '.$pri.'
      my $scoresptr = $self->{conf}->{scores};

  ';

  if ($self->{main}->have_plugin("start_rules")) {
    $evalstr .= '

      $self->{main}->call_plugins ("start_rules", { permsgstatus => $self,
                                                    ruletype => \''.$ruletype.'\',
                                                    priority => '.$pri.' });

    ';
  }

  return $evalstr;
}

sub hit_rule_plugin_code {
  my ($self, $pms, $rulename, $ruletype, $loop_break_directive) = @_;

  # note: keep this in 'single quotes' to avoid the $ & performance hit,
  # unless specifically requested by the caller.   Also split the
  # two chars, just to be paranoid and ensure that a buggy perl interp
  # doesn't impose that hit anyway (just in case)
  my $match = '($' . '&' . '|| "negative match")';

  my $debug_code = '';
  if (exists($pms->{should_log_rule_hits})) {
    $debug_code = '
        dbg("rules: ran '.$ruletype.' rule '.$rulename.' ======> got hit: \"" . '.
            $match.' . "\"");
    ';
  }

  my $save_hits_code = '';
  if ($pms->{save_pattern_hits}) {
    $save_hits_code = '
        $self->{pattern_hits}->{q{'.$rulename.'}} = '.$match.';
    ';
  }

  # if we're not running "tflags multiple", break out of the matching
  # loop this way
  my $multiple_code = '';
  if (($pms->{conf}->{tflags}->{$rulename}||'') !~ /\bmultiple\b/) {
    $multiple_code = $loop_break_directive.';';
  }

  return $debug_code.$save_hits_code.$multiple_code;
}

sub ran_rule_plugin_code {
  my ($self, $rulename, $ruletype) = @_;

  return '' unless $self->{main}->have_plugin("ran_rule");

  # The $self here looks odd, but since we are inserting this into eval'd code it
  # needs to be $self which in that case is actually the PerMsgStatus object
  return '
    $self->{main}->call_plugins ("ran_rule", { permsgstatus => $self, rulename => \''.$rulename.'\', ruletype => \''.$ruletype.'\' });
  ';
}

sub free_ruleset_source {
  my ($self, $pms, $type, $pri) = @_;

  # we can't do this, if we may need to recompile them again later
  return if $pms->{conf}->{allow_user_rules};

  # remove now-compiled rulesets
  if (exists $pms->{conf}->{$type.'_tests'}->{$pri}) {
    delete $pms->{conf}->{$type.'_tests'}->{$pri};
  }
}

###########################################################################

1;
