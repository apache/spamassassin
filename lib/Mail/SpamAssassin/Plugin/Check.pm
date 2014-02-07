=head1 NAME

Mail::SpamAssassin::Plugin::Check - primary message check functionality

=head1 SYNOPSIS

loadplugin Mail::SpamAssassin::Plugin::Check

=head1 DESCRIPTION

This plugin provides the primary message check functionality.

=cut

package Mail::SpamAssassin::Plugin::Check;

use strict;
use warnings;
use re 'taint';

use Time::HiRes qw(time);

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Util qw(untaint_var);
use Mail::SpamAssassin::Timeout;
use Mail::SpamAssassin::Constants qw(:sa);

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

  my $suppl_attrib = $pms->{msg}->{suppl_attrib};
  if (ref $suppl_attrib && ref $suppl_attrib->{rule_hits}) {
    my @caller_rule_hits = @{$suppl_attrib->{rule_hits}};
    dbg("check: adding caller rule hits, %d rules", scalar(@caller_rule_hits));
    for my $caller_rule_hit (@caller_rule_hits) {
      next if ref $caller_rule_hit ne 'HASH';
      my($rulename, $area, $score, $defscore, $value,
         $ruletype, $tflags, $description) =
        @$caller_rule_hit{qw(rule area score defscore value
                             ruletype tflags descr)};
      $pms->got_hit($rulename, $area,
                    !defined $score ? () : (score => $score),
                    !defined $defscore ? () : (defscore => $defscore),
                    !defined $value ? () : (value => $value),
                    !defined $tflags ? () : (tflags => $tflags),
                    !defined $description ? () : (description => $description),
                    ruletype => $ruletype);
    }
  }

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
  my $master_deadline = $pms->{master_deadline};
  dbg("check: check_main, time limit in %.3f s",
      $master_deadline - time)  if $master_deadline;

  my @uris = $pms->get_uri_list();

  foreach my $priority (sort { $a <=> $b } keys %{$pms->{conf}->{priorities}}) {
    # no need to run if there are no priorities at this level.  This can
    # happen in Conf.pm when we switch a rule from one priority to another
    next unless ($pms->{conf}->{priorities}->{$priority} > 0);

    if ($pms->{deadline_exceeded}) {
      last;
    } elsif ($master_deadline && time > $master_deadline) {
      info("check: exceeded time limit, skipping further tests");
      $pms->{deadline_exceeded} = 1;
      last;
    } elsif ($self->{main}->call_plugins("have_shortcircuited",
                                         { permsgstatus => $pms })) {
      # if shortcircuiting is hit, we skip all other priorities...
      last;
    }

    my $timer = $self->{main}->time_method("tests_pri_".$priority);
    dbg("check: running tests for priority: $priority");

    # only harvest the dnsbl queries once priority HARVEST_DNSBL_PRIORITY
    # has been reached and then only run once
    #
    # TODO: is this block still needed here? is HARVEST_DNSBL_PRIORITY used?
    #
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

    $pms->harvest_completed_queries();
    # allow other, plugin-defined rule types to be called here
    $self->{main}->call_plugins ("check_rules_at_priority",
        { permsgstatus => $pms, priority => $priority, checkobj => $self });

    # do head tests
    $self->do_head_tests($pms, $priority);
    $pms->harvest_completed_queries();
    last if $pms->{deadline_exceeded};

    $self->do_head_eval_tests($pms, $priority);
    $pms->harvest_completed_queries();
    last if $pms->{deadline_exceeded};

    $self->do_body_tests($pms, $priority, $decoded);
    $pms->harvest_completed_queries();
    last if $pms->{deadline_exceeded};

    $self->do_uri_tests($pms, $priority, @uris);
    $pms->harvest_completed_queries();
    last if $pms->{deadline_exceeded};

    $self->do_body_eval_tests($pms, $priority, $decoded);
    $pms->harvest_completed_queries();
    last if $pms->{deadline_exceeded};
  
    $self->do_rawbody_tests($pms, $priority, $bodytext);
    $pms->harvest_completed_queries();
    last if $pms->{deadline_exceeded};

    $self->do_rawbody_eval_tests($pms, $priority, $bodytext);
    $pms->harvest_completed_queries();
    last if $pms->{deadline_exceeded};
  
    $self->do_full_tests($pms, $priority, \$fulltext);
    $pms->harvest_completed_queries();
    last if $pms->{deadline_exceeded};

    $self->do_full_eval_tests($pms, $priority, \$fulltext);
    $pms->harvest_completed_queries();
    last if $pms->{deadline_exceeded};

    $self->do_meta_tests($pms, $priority);
    $pms->harvest_completed_queries();
    last if $pms->{deadline_exceeded};

    # we may need to call this more often than once through the loop, but
    # it needs to be done at least once, either at the beginning or the end.
    $self->{main}->call_plugins ("check_tick", { permsgstatus => $pms });
    $pms->harvest_completed_queries();
    last if $pms->{deadline_exceeded};
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

  if ($pms->{deadline_exceeded}) {
    $pms->got_hit('TIME_LIMIT_EXCEEDED', '', defscore => 0.001,
                  description => 'Exceeded time limit / deadline');
  }

  # finished running rules
  delete $pms->{current_rule_name};
  undef $decoded;
  undef $bodytext;
  undef $fulltext;

  if ($pms->{deadline_exceeded}) {
  # dbg("check: exceeded time limit, skipping auto-learning");
  } elsif ($master_deadline && time > $master_deadline) {
    info("check: exceeded time limit, skipping auto-learning");
    $pms->{deadline_exceeded} = 1;
  } else {
    # auto-learning
    $pms->learn();
    $self->{main}->call_plugins ("check_post_learn", { permsgstatus => $pms });
  }

  # track user_rules recompilations; each scanned message is 1 tick on this counter
  if ($self->{done_user_rules}) {
    my $counters = $pms->{conf}->{want_rebuild_for_type};
    foreach my $type (keys %{$self->{done_user_rules}}) {
      if ($counters->{$type} > 0) {
        $counters->{$type}--;
      }
      dbg("rules: user rules done; ticking want_rebuild counter for type $type to ".
                    $counters->{$type});
    }
  }

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

    %{$pms->{test_log_msgs}} = ();        # clear test state

    my ($function, @args) = @{$test};

    my $result;
    eval {
      $result = $pms->$function($rulename, @args);  1;
    } or do {
      my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
      die "rules: $eval_stat\n"  if $eval_stat =~ /__alarm__ignore__/;
      warn "rules: failed to run $rulename RBL test, skipping:\n".
           "\t($eval_stat)\n";
      $pms->{rule_errors}++;
      next;
    };
  }
}

###########################################################################

sub run_generic_tests {
  my ($self, $pms, $priority, %opts) = @_;

  my $master_deadline = $pms->{master_deadline};
  if ($pms->{deadline_exceeded}) {
    return;
  } elsif ($master_deadline && time > $master_deadline) {
    info("check: (run_generic) exceeded time limit, skipping further tests");
    $pms->{deadline_exceeded} = 1;
    return;
  } elsif ($self->{main}->call_plugins("have_shortcircuited",
                                        { permsgstatus => $pms })) {
    return;
  }

  my $ruletype = $opts{type};
  dbg("rules: running $ruletype tests; score so far=".$pms->{score});
  %{$pms->{test_log_msgs}} = ();        # clear test state

  my $conf = $pms->{conf};
  my $doing_user_rules = $conf->{want_rebuild_for_type}->{$opts{consttype}};
  if ($doing_user_rules) { $self->{done_user_rules}->{$opts{consttype}}++; }

  # clean up priority value so it can be used in a subroutine name
  my $clean_priority;
  ($clean_priority = $priority) =~ s/-/neg/;
  my $package_name = __PACKAGE__;
  my $methodname = $package_name."::_".$ruletype."_tests_".$clean_priority;

  if (!defined &{$methodname} || $doing_user_rules) {

    # use %nopts for named parameter-passing; it's more friendly
    # to future-proof subclassing, since new parameters can be added without
    # breaking third-party subclassed implementations of this plugin.
    my %nopts = (
      ruletype => $ruletype,
      doing_user_rules => $doing_user_rules,
      priority => $priority,
      clean_priority => $clean_priority
    );

    # build up the eval string...
    $self->{evalstr_methodname} = $methodname;
    $self->{evalstr_chunk_current_methodname} = undef;
    $self->{evalstr_chunk_methodnames} = [];
    $self->{evalstr_chunk_prefix} = []; # stack (array) of source code sections
    $self->{evalstr} = ''; $self->{evalstr_l} = 0;
    $self->{evalstr2} = '';
    $self->begin_evalstr_chunk($pms);

    $self->push_evalstr_prefix($pms, '
        # start_rules_plugin_code '.$ruletype.' '.$priority.'
        my $scoresptr = $self->{conf}->{scores};
    ');
    if (defined $opts{pre_loop_body}) {
      $opts{pre_loop_body}->($self, $pms, $conf, %nopts);
    }
    $self->add_evalstr($pms,
                       $self->start_rules_plugin_code($ruletype, $priority) );
    while (my($rulename, $test) = each %{$opts{testhash}->{$priority}}) {
      $opts{loop_body}->($self, $pms, $conf, $rulename, $test, %nopts);
    }
    if (defined $opts{post_loop_body}) {
      $opts{post_loop_body}->($self, $pms, $conf, %nopts);
    }

   # dbg("rules: generated matching code:\n".$self->{evalstr});

    $self->flush_evalstr($pms, 'run_generic_tests');
    $self->free_ruleset_source($pms, $ruletype, $priority);

    # clear out a previous version of this method
    undef &{$methodname};

    # generate the loop that goes through each line...
    my $evalstr = <<"EOT";
  {
    package $package_name;

    $self->{evalstr2}

    sub $methodname {
EOT

    for my $chunk_methodname (@{$self->{evalstr_chunk_methodnames}}) {
      $evalstr .= "      $chunk_methodname(\@_);\n";
    }

    $evalstr .= <<"EOT";
    }

    1;
  }
EOT

    delete $self->{evalstr};   # free up some RAM before we eval()
    delete $self->{evalstr2};
    delete $self->{evalstr_methodname};
    delete $self->{evalstr_chunk_current_methodname};
    delete $self->{evalstr_chunk_methodnames};
    delete $self->{evalstr_chunk_prefix};

    dbg("rules: run_generic_tests - compiling eval code: %s, priority %s",
        $ruletype, $priority);
  # dbg("rules: eval code to compile: %s", $evalstr);
    my $eval_result;
    { my $timer = $self->{main}->time_method('compile_gen');
      $eval_result = eval($evalstr);
    }
    if (!$eval_result) {
      my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
      warn "rules: failed to compile $ruletype tests, skipping:\n".
           "\t($eval_stat)\n";
      $pms->{rule_errors}++;
      return;
    }
    dbg("rules: compiled $ruletype tests");
  }

#run_compiled_method:
# dbg("rules: run_generic_tests - calling %s", $methodname);
  my $t = Mail::SpamAssassin::Timeout->new({ deadline => $master_deadline });
  my $err = $t->run(sub {
    no strict "refs";
    $methodname->($pms, @{$opts{args}});
  });
  if ($t->timed_out() && $master_deadline && time > $master_deadline) {
    info("check: exceeded time limit in $methodname, skipping further tests");
    $pms->{deadline_exceeded} = 1;
  }
}

sub begin_evalstr_chunk {
  my ($self, $pms) = @_;
  my $n = 0;
  if ($self->{evalstr_chunk_methodnames}) {
    $n = scalar(@{$self->{evalstr_chunk_methodnames}});
  }
  my $chunk_methodname = sprintf("%s_%d", $self->{evalstr_methodname}, $n+1);
# dbg("rules: begin_evalstr_chunk %s", $chunk_methodname);
  undef &{$chunk_methodname};
  my $package_name = __PACKAGE__;
  my $evalstr = <<"EOT";
package $package_name;
sub $chunk_methodname {
  my \$self = shift;
  my \$hits = 0;
EOT
  $evalstr .= '  '.$_  for @{$self->{evalstr_chunk_prefix}};
  $self->{evalstr} = $evalstr;
  $self->{evalstr_l} = length($evalstr);
  $self->{evalstr_chunk_current_methodname} = $chunk_methodname;
}

sub end_evalstr_chunk {
  my ($self, $pms) = @_;
# dbg("rules: end_evalstr_chunk");
  my $evalstr = "}; 1;\n";
  $self->{evalstr} .= $evalstr;
  $self->{evalstr_l} += length($evalstr);
}

sub flush_evalstr {
  my ($self, $pms, $caller_name) = @_;
  my $chunk_methodname = $self->{evalstr_chunk_current_methodname};
  $self->end_evalstr_chunk($pms);
  dbg("rules: flush_evalstr (%s) compiling %d chars of %s",
      $caller_name, $self->{evalstr_l}, $chunk_methodname);
# dbg("rules: eval code(2): %s", $self->{evalstr});
  my $eval_result;
  { my $timer = $self->{main}->time_method('compile_gen');
    $eval_result = eval($self->{evalstr});
  }
  if (!$eval_result) {
    my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
    warn "rules: failed to compile $chunk_methodname, skipping:\n".
         "\t($eval_stat)\n";
    $pms->{rule_errors}++;
  } else {
    push(@{$self->{evalstr_chunk_methodnames}}, $chunk_methodname);
  }
  $self->{evalstr} = '';  $self->{evalstr_l} = 0;
  $self->begin_evalstr_chunk($pms);
}

sub push_evalstr_prefix {
  my ($self, $pms, $str) = @_;
  $self->add_evalstr_corked($pms, $str);  # must not flush!
  push(@{$self->{evalstr_chunk_prefix}}, $str);
# dbg("rules: push_evalstr_prefix (%d) - <%s>",
#     scalar(@{$self->{evalstr_chunk_prefix}}), $str);
}

sub pop_evalstr_prefix {
  my ($self) = @_;
  pop(@{$self->{evalstr_chunk_prefix}});
# dbg("rules: pop_evalstr_prefix (%d)",
#     scalar(@{$self->{evalstr_chunk_prefix}}));
}

sub add_evalstr {
  my ($self, $pms, $str) = @_;
  if (defined $str && $str ne '') {
    my $new_code_l = length($str);
  # dbg("rules: add_evalstr %d - <%s>", $new_code_l, $str);
    $self->{evalstr} .= $str;
    $self->{evalstr_l} += $new_code_l;
    if ($self->{evalstr_l} > 60000) {
      $self->flush_evalstr($pms, 'add_evalstr');
    }
  }
}

# similar to add_evalstr, but avoids flushing on size
sub add_evalstr_corked {
  my ($self, $pms, $str) = @_;
  if (defined $str) {
    my $new_code_l = length($str);
    $self->{evalstr} .= $str;
    $self->{evalstr_l} += $new_code_l;
  }
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
    $rule = untaint_var($rule);  # presumably checked

    # Lex the rule into tokens using a rather simple RE method ...
    my $lexer = ARITH_EXPRESSION_LEXER;
    my @tokens = ($rule =~ m/$lexer/g);

    # Set the rule blank to start
    $meta{$rulename} = "";

    # List dependencies that are meta tests in the same priority band
    $rule_deps{$rulename} = [ ];

    # Go through each token in the meta rule
    foreach my $token (@tokens) {

      # Numbers can't be rule names
    # if ($token =~ /^(?:\W+|[+-]?\d+(?:\.\d+)?)$/) {
      if ($token !~ /^[A-Za-z_][A-Za-z0-9_]*\z/s) {  # faster
        $meta{$rulename} .= "$token ";
      }
      else {  # token is a rule name
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
    $self->push_evalstr_prefix($pms, '
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
        if (!defined $conf->{meta_dependencies}->{ $metas[$i] }) {
          warn "no meta_dependencies defined for $metas[$i]";
        }
        my $alldeps = join ' ', grep {
                ($tflags->{$_}||'') =~ /\bnet\b/
              } split (' ', $conf->{meta_dependencies}->{ $metas[$i] } );

        if ($alldeps ne '') {
          $self->add_evalstr($pms, '
            $self->ensure_rules_are_complete(q{'.$metas[$i].'}, qw{'.$alldeps.'});
          ');
        }

        # Add this meta rule to the eval line
        $self->add_evalstr($pms, '
          $r = '.$meta{$metas[$i]}.';
          if ($r) { $self->got_hit(q#'.$metas[$i].'#, "", ruletype => "meta", value => $r); }
        ');

        splice @metas, $i--, 1;    # remove this rule from our list
      }
    } while ($#metas != $count && $#metas > -1); # run until we can't go anymore

    # If there are any rules left, we can't solve the dependencies so complain
    my %metas = map { $_ => 1 } @metas; # keep a small cache for fast lookups
    foreach my $rulename_t (@metas) {
      $pms->{rule_errors}++; # flag to --lint that there was an error ...
      my $msg =
          "rules: excluding meta test $rulename_t, unsolved meta dependencies: " .
              join(", ", grep($metas{$_}, @{ $rule_deps{$rulename_t} }));
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
  my %ordered;
  my %testcode;  # tuples: [op_type, op, arg]
     # op_type: 1=infix, 0:prefix/function
     # op: operator, e.g. '=~', '!~', or a function like 'defined'
     # arg: additional argument like a regexp for a patt matching op

  $self->run_generic_tests ($pms, $priority,
    consttype => $Mail::SpamAssassin::Conf::TYPE_HEAD_TESTS,
    type => 'head',
    testhash => $pms->{conf}->{head_tests},
    args => [ ],
    loop_body => sub
  {
    my ($self, $pms, $conf, $rulename, $rule, %opts) = @_;
    my $def;
    $rule = untaint_var($rule);  # presumably checked
    my ($hdrname, $op, $op_infix, $pat);
    if ($rule =~ /^\s* (\S+) \s* ([=!]~) \s* (\S .*? \S) \s*$/x) {
      ($hdrname, $op, $pat) = ($1,$2,$3);  # e.g.: Subject =~ /patt/
      $op_infix = 1;
      if (!defined $pat) {
        warn "rules: invalid rule: $rulename\n";
        $pms->{rule_errors}++;
        next;
      }
      if ($pat =~ s/\s+\[if-unset:\s+(.+)\]\s*$//) { $def = $1 }
    } elsif ($rule =~ /^\s* (\S+) \s* \( \s* (\S+) \s* \) \s*$/x) {
      # implements exists:name_of_header (and similar function or prefix ops)
      ($hdrname, $op) = ($2,$1);  # e.g.: !defined(Subject)
      $op_infix = 0;
    } else {
      warn "rules: unrecognized rule: $rulename\n";
      $pms->{rule_errors}++;
      next;
    }

    push(@{ $ordered{$hdrname . (!defined $def ? '' : "\t".$def)} },
         $rulename);

    next if ($opts{doing_user_rules} &&
            !$self->is_user_rule_sub($rulename.'_head_test'));

    # caller can set this member of the Mail::SpamAssassin object to
    # override this; useful for profiling rule runtimes, although I think
    # the HitFreqsRuleTiming.pm plugin is probably better nowadays anyway
    if ($self->{main}->{use_rule_subs}) {
      my $matching_string_unavailable = 0;
      my $expr;
      if ($op =~ /^!?[A-Za-z_]+$/) {  # function or its negation
        $expr = $op . '($text)';
        $matching_string_unavailable = 1;
      } else {  # infix operator
        $expr = '$text ' . $op . ' ' . $pat;
        if ($op eq '=~' || $op eq '!~') {
          $expr .= 'g';
        } else {
          $matching_string_unavailable = 1;
        }
      }
      $self->add_temporary_method ($rulename.'_head_test', '{
          my($self,$text) = @_;
          '.$self->hash_line_for_rule($pms, $rulename).'
	    while ('.$expr.') {
            $self->got_hit(q{'.$rulename.'}, "", ruletype => "header");
            '. $self->hit_rule_plugin_code($pms, $rulename, "header", "last",
                                           $matching_string_unavailable) . '
            }
        }');
    }
    else {
      # store for use below
      $testcode{$rulename} = [$op_infix, $op, $pat];
    }
  },
    pre_loop_body => sub
  {
    my ($self, $pms, $conf, %opts) = @_;
    $self->push_evalstr_prefix($pms, '
      no warnings q(uninitialized);
      my $hval;
    ');
  },
    post_loop_body => sub
  {
    my ($self, $pms, $conf, %opts) = @_;
    # setup the function to run the rules
    while(my($k,$v) = each %ordered) {
      my($hdrname, $def) = split(/\t/, $k, 2);
      $self->push_evalstr_prefix($pms, '
        $hval = $self->get(q{'.$hdrname.'}, ' .
                           (!defined($def) ? 'undef' : 'q{'.$def.'}') . ');
      ');
      foreach my $rulename (@{$v}) {
        if ($self->{main}->{use_rule_subs}) {
          $self->add_evalstr($pms, '
            if ($scoresptr->{q{'.$rulename.'}}) {
              '.$rulename.'_head_test($self, $hval);
              '.$self->ran_rule_plugin_code($rulename, "header").'
            }
          ');
        }
        else {
          my $tc_ref = $testcode{$rulename};
          my ($op_infix, $op, $pat);
          ($op_infix, $op, $pat) = @$tc_ref  if defined $tc_ref;

          my $posline = '';
          my $ifwhile = 'if';
          my $hitdone = '';
          my $matchg = '';
          my $whlimit = '';

          my $matching_string_unavailable = 0;
          my $expr;
          if (!$op_infix) {  # function or its negation
            $expr = $op . '($hval)';
            $matching_string_unavailable = 1;
          }
          else {  # infix operator
            if (! ($op eq '=~' || $op eq '!~') ) { # not a pattern matching op.
              $matching_string_unavailable = 1;
            } elsif ( ($conf->{tflags}->{$rulename}||'') =~ /\bmultiple\b/ ) {
              $posline = 'pos $hval = 0; $hits = 0;';
              $ifwhile = 'while';
              $hitdone = 'last';
              $matchg = 'g';
              my ($max) = ($pms->{conf}->{tflags}->{$rulename}||'') =~ /\bmaxhits=(\d+)\b/;
              $max = untaint_var($max);
              $whlimit = ' && $hits++ < '.$max if $max;
            }
            $expr = '$hval ' . $op . ' ' . $pat . $matchg;
          }

          $self->add_evalstr($pms, '
          if ($scoresptr->{q{'.$rulename.'}}) {
            '.$posline.'
            '.$self->hash_line_for_rule($pms, $rulename).'
            '.$ifwhile.' ('.$expr.$whlimit.') {
              $self->got_hit(q{'.$rulename.'}, "", ruletype => "header");
              '.$self->hit_rule_plugin_code($pms, $rulename, "header", $hitdone,
                                            $matching_string_unavailable).'
            }
            '.$self->ran_rule_plugin_code($rulename, "header").'
          }
          ');
        }
      }
      $self->pop_evalstr_prefix();
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
    $pat = untaint_var($pat);  # presumably checked
    my $sub = '';
    if (would_log('dbg', 'rules-all') == 2) {
      $sub .= '
      dbg("rules-all: running body rule %s", q{'.$rulename.'});
      ';
    }
    if (($conf->{tflags}->{$rulename}||'') =~ /\bmultiple\b/)
    {
      # support multiple matches
      $loopid++;
      my ($max) = ($pms->{conf}->{tflags}->{$rulename}||'') =~ /\bmaxhits=(\d+)\b/;
      $max = untaint_var($max);
      $sub .= '
      $hits = 0;
      body_'.$loopid.': foreach my $l (@_) {
        pos $l = 0;
        '.$self->hash_line_for_rule($pms, $rulename).'
        while ($l =~ '.$pat.'g'. ($max? ' && $hits++ < '.$max:'') .') { 
          $self->got_hit(q{'.$rulename.'}, "BODY: ", ruletype => "body"); 
          '. $self->hit_rule_plugin_code($pms, $rulename, 'body',
					 "last body_".$loopid) . '
        }
        '. ($max? 'last body_'.$loopid.' if $hits > '. $max .';':'') .'
      }
      ';
    }
    else {
      # omitting the "pos" call, "body_loopid" label, use of while()
      # instead of if() etc., shaves off 8 perl OPs.
      $sub .= '
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
      $self->add_evalstr($pms, '
        if ($scoresptr->{q{'.$rulename.'}}) {
          '.$rulename.'_body_test($self,@_); 
          '.$self->ran_rule_plugin_code($rulename, "body").'
        }
      ');
    }
    else {
      $self->add_evalstr($pms, '
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
    $pat = untaint_var($pat);  # presumably checked
    my $sub = '';
    if (would_log('dbg', 'rules-all') == 2) {
      $sub .= '
      dbg("rules-all: running uri rule %s", q{'.$rulename.'});
      ';
    }
    if (($conf->{tflags}->{$rulename}||'') =~ /\bmultiple\b/) {
      $loopid++;
      my ($max) = ($pms->{conf}->{tflags}->{$rulename}||'') =~ /\bmaxhits=(\d+)\b/;
      $max = untaint_var($max);
      $sub .= '
      $hits = 0;
      uri_'.$loopid.': foreach my $l (@_) {
        pos $l = 0;
        '.$self->hash_line_for_rule($pms, $rulename).'
        while ($l =~ '.$pat.'g'. ($max? ' && $hits++ < '.$max:'') .') { 
           $self->got_hit(q{'.$rulename.'}, "URI: ", ruletype => "uri");
           '. $self->hit_rule_plugin_code($pms, $rulename, "uri",
					  "last uri_".$loopid) . '
        }
        '. ($max? 'last uri_'.$loopid.' if $hits > '. $max .';':'') .'
      }
      ';
    } else {
      $sub .= '
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
      $self->add_evalstr($pms, '
        if ($scoresptr->{q{'.$rulename.'}}) {
          '.$rulename.'_uri_test($self, @_);
          '.$self->ran_rule_plugin_code($rulename, "uri").'
        }
      ');
    }
    else {
      $self->add_evalstr($pms, '
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
    $pat = untaint_var($pat);  # presumably checked
    my $sub = '';
    if (would_log('dbg', 'rules-all') == 2) {
      $sub .= '
      dbg("rules-all: running rawbody rule %s", q{'.$rulename.'});
      ';
    }
    if (($pms->{conf}->{tflags}->{$rulename}||'') =~ /\bmultiple\b/)
    {
      # support multiple matches
      $loopid++;
      my ($max) = ($pms->{conf}->{tflags}->{$rulename}||'') =~ /\bmaxhits=(\d+)\b/;
      $max = untaint_var($max);
      $sub .= '
      $hits = 0;
      rawbody_'.$loopid.': foreach my $l (@_) {
        pos $l = 0;
        '.$self->hash_line_for_rule($pms, $rulename).'
        while ($l =~ '.$pat.'g'. ($max? ' && $hits++ < '.$max:'') .') { 
           $self->got_hit(q{'.$rulename.'}, "RAW: ", ruletype => "rawbody");
           '. $self->hit_rule_plugin_code($pms, $rulename, "rawbody",
					  "last rawbody_".$loopid) . '
        }
        '. ($max? 'last rawbody_'.$loopid.' if $hits > '. $max .';':'') .'
      }
      ';
    }
    else {
      $sub .= '
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
      $self->add_evalstr($pms, '
        if ($scoresptr->{q{'.$rulename.'}}) {
           '.$rulename.'_rawbody_test($self, @_);
           '.$self->ran_rule_plugin_code($rulename, "rawbody").'
        }
      ');
    }
    else {
      $self->add_evalstr($pms, '
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
    $self->push_evalstr_prefix($pms, '
      my $fullmsgref = shift;
    ');
  },
                loop_body => sub
  {
    my ($self, $pms, $conf, $rulename, $pat, %opts) = @_;
    $pat = untaint_var($pat);  # presumably checked
    my ($max) = ($pms->{conf}->{tflags}->{$rulename}||'') =~ /\bmaxhits=(\d+)\b/;
    $max = untaint_var($max);
    $self->add_evalstr($pms, '
      if ($scoresptr->{q{'.$rulename.'}}) {
        pos $$fullmsgref = 0;
        '.$self->hash_line_for_rule($pms, $rulename).'
        dbg("rules-all: running full rule %s", q{'.$rulename.'});
        $hits = 0;
        while ($$fullmsgref =~ '.$pat.'g'. ($max? ' && $hits++ < '.$max:'') .') {
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
  dbg("rules: running head_eval tests; score so far=".$pms->{score});
  $self->run_eval_tests ($pms, $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS,
			 $pms->{conf}->{head_evals}->{$priority}, '', $priority);
}

sub do_body_eval_tests {
  my ($self, $pms, $priority, $bodystring) = @_;
  return unless (defined($pms->{conf}->{body_evals}->{$priority}));
  dbg("rules: running body_eval tests; score so far=".$pms->{score});
  $self->run_eval_tests ($pms, $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS,
			 $pms->{conf}->{body_evals}->{$priority}, 'BODY: ',
			 $priority, $bodystring);
}

sub do_rawbody_eval_tests {
  my ($self, $pms, $priority, $bodystring) = @_;
  return unless (defined($pms->{conf}->{rawbody_evals}->{$priority}));
  dbg("rules: running rawbody_eval tests; score so far=".$pms->{score});
  $self->run_eval_tests ($pms, $Mail::SpamAssassin::Conf::TYPE_RAWBODY_EVALS,
			 $pms->{conf}->{rawbody_evals}->{$priority}, 'RAW: ',
			 $priority, $bodystring);
}

sub do_full_eval_tests {
  my ($self, $pms, $priority, $fullmsgref) = @_;
  return unless (defined($pms->{conf}->{full_evals}->{$priority}));
  dbg("rules: running full_eval tests; score so far=".$pms->{score});
  $self->run_eval_tests($pms, $Mail::SpamAssassin::Conf::TYPE_FULL_EVALS,
			$pms->{conf}->{full_evals}->{$priority}, '',
			$priority, $fullmsgref);
}

sub run_eval_tests {
  my ($self, $pms, $testtype, $evalhash, $prepend2desc, $priority, @extraevalargs) = @_;
 
  my $master_deadline = $pms->{master_deadline};
  if ($pms->{deadline_exceeded}) {
    return;
  } elsif ($master_deadline && time > $master_deadline) {
    info("check: (run_eval) exceeded time limit, skipping further tests");
    $pms->{deadline_exceeded} = 1;
    return;
  } elsif ($self->{main}->call_plugins("have_shortcircuited",
                                        { permsgstatus => $pms })) {
    return;
  }

  my $conf = $pms->{conf};
  my $doing_user_rules = $conf->{want_rebuild_for_type}->{$testtype};
  if ($doing_user_rules) { $self->{done_user_rules}->{$testtype}++; }

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
    my $method = "${package_name}::${methodname}";
  # dbg("rules: run_eval_tests - calling previously compiled %s", $method);
    my $t = Mail::SpamAssassin::Timeout->new({ deadline => $master_deadline });
    my $err = $t->run(sub {
      no strict "refs";
      &{$method}($pms,@extraevalargs);
    });
    if ($t->timed_out() && $master_deadline && time > $master_deadline) {
      info("check: exceeded time limit in $method, skipping further tests");
      $pms->{deadline_exceeded} = 1;
    }
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
 
    $test = untaint_var($test);  # presumably checked
    my ($function, $argstr) = ($test,'');
    if ($test =~ s/^([^,]+)(,.*)$//gs) {
      ($function, $argstr) = ($1,$2);
    }

    if (!$function) {
      warn "rules: error: no function defined for $rulename";
      next;
    }
 
    $evalstr .= '
    if ($scoresptr->{q#'.$rulename.'#}) {
      $rulename = q#'.$rulename.'#;
      %{$self->{test_log_msgs}} = ();
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
        $result = $self->' . $function . ' (@extraevalargs '. $argstr .' );  1;
      } or do {
        $result = 0;
        die "rules: $@\n"  if $@ =~ /__alarm__ignore__/;
        $self->handle_eval_rule_errors($rulename);
      };

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

      my \$scoresptr = \$self->{conf}->{scores};
      my \$prepend2desc = q#$prepend2desc#;
      my \$rulename;
      my \$result;

      $evalstr
    }

  1;
}
EOT

  undef &{$methodname};

  dbg("rules: run_eval_tests - compiling eval code: %s, priority %s",
       $testtype, $priority);
# dbg("rules: eval code(3): %s", $evalstr);
  my $eval_result;
  { my $timer = $self->{main}->time_method('compile_eval');
    $eval_result = eval($evalstr);
  }
  if (!$eval_result) {
    my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
    warn "rules: failed to compile eval tests, skipping some: $eval_stat\n";
    $self->{rule_errors}++;
  }
  else {
    my $method = "${package_name}::${methodname}";
    push (@TEMPORARY_METHODS, $methodname);
  # dbg("rules: run_eval_tests - calling the just compiled %s", $method);
    my $t = Mail::SpamAssassin::Timeout->new({ deadline => $master_deadline });
    my $err = $t->run(sub {
      no strict "refs";
      &{$method}($pms,@extraevalargs);
    });
    if ($t->timed_out() && $master_deadline && time > $master_deadline) {
      info("check: exceeded time limit in $method, skipping further tests");
      $pms->{deadline_exceeded} = 1;
    }
  }
}

###########################################################################
# Helper Functions

sub hash_line_for_rule {
  my ($self, $pms, $rulename) = @_;
  # using tainted subr. argument may taint the whole expression, avoid
  my $u = untaint_var($pms->{conf}->{source_file}->{$rulename});
  return sprintf("\n#line 1 \"%s, rule %s,\"", $u, $rulename);
# return sprintf("\n#line 1 \"%s, rule %s,\"", $u, $rulename) .
#        "\ndbg(\"rules: will run %s\", q(".$rulename."));\n";
}

sub is_user_rule_sub {
  my ($self, $subname) = @_;
  my $package_name = __PACKAGE__;
  return 0 if (eval 'defined &'.$package_name.'::'.$subname);
  1;
}

sub start_rules_plugin_code {
  my ($self, $ruletype, $pri) = @_;

  my $evalstr = '';
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
  my ($self, $pms, $rulename, $ruletype, $loop_break_directive,
      $matching_string_unavailable) = @_;

  # note: keep this in 'single quotes' to avoid the $ & performance hit,
  # unless specifically requested by the caller.   Also split the
  # two chars, just to be paranoid and ensure that a buggy perl interp
  # doesn't impose that hit anyway (just in case)
  my $match;
  if ($matching_string_unavailable) {
    $match = '"<YES>"'; # nothing better to report, $& is not set by this rule
  } else {
    # simple, but suffers from 'user data interpreted as a boolean', Bug 6360
    $match = '($' . '&' . '|| "negative match")';
  }

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
