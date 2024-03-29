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

our @ISA = qw(Mail::SpamAssassin::Plugin);

# methods defined by the compiled ruleset; deleted in finish_tests()
our @TEMPORARY_METHODS;

# will cache would_log('dbg', 'rules-all') later
my $would_log_rules_all = 0;

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
  my $conf = $pms->{conf};
  $would_log_rules_all = would_log('dbg', 'rules-all') == 2;

  # Make AsyncLoop wait launch_queue() for launching queries
  $pms->{async}->start_queue();

  # initialize meta stuff
  $pms->{meta_pending} = {};
  foreach my $rulename (keys %{$conf->{meta_tests}}) {
    $pms->{meta_pending}->{$rulename} = 1  if $conf->{scores}->{$rulename};
  }
  # metas without dependencies are ready to be run
  foreach my $rulename (keys %{$conf->{meta_nodeps}}) {
    $pms->{meta_check_ready}->{$rulename} = 1;
  }

  # rule_hits API implemented in 3.3.0
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
      dbg("rules: ran rule_hits rule $rulename ======> got hit (%s)",
          defined $value ? $value : '1');
      $pms->got_hit($rulename, $area,
                    !defined $score ? () : (score => $score),
                    !defined $defscore ? () : (defscore => $defscore),
                    !defined $value ? () : (value => $value),
                    !defined $tflags ? () : (tflags => $tflags),
                    !defined $description ? () : (description => $description),
                    ruletype => $ruletype);
      delete $pms->{meta_pending}->{$rulename};
      delete $pms->{meta_check_ready}->{$rulename};
    }
  }

  # bug 4353:
  # Do this before the RBL tests are kicked off.  The metadata parsing
  # will figure out the (un)trusted relays and such, which are used in the
  # rbl calls.
  $pms->extract_message_metadata();

  my $do_dns = $pms->is_dns_available();
  my $rbls_running = 0;

  my $decoded = $pms->get_decoded_stripped_body_text_array();
  my $bodytext = $pms->get_decoded_body_text_array();
  my $fulltext = $pms->{msg}->get_pristine();
  my $master_deadline = $pms->{master_deadline};
  dbg("check: check_main, time limit in %.3f s",
      $master_deadline - time)  if $master_deadline;

  # Make sure priority -100 exists for launching DNS
  $conf->{priorities}->{-100} ||= 1 if $do_dns;

  my @priorities = sort { $a <=> $b } keys %{$conf->{priorities}};
  foreach my $priority (@priorities) {
    # no need to run if there are no priorities at this level.  This can
    # happen in Conf.pm when we switch a rule from one priority to another
    next unless ($conf->{priorities}->{$priority} > 0);

    if ($pms->{deadline_exceeded}) {
      last;
    } elsif ($master_deadline && time > $master_deadline) {
      info("check: exceeded time limit, skipping further tests");
      $pms->{deadline_exceeded} = 1;
      last;
    } elsif ($self->{main}->call_plugins("have_shortcircuited",
                                         { permsgstatus => $pms })) {
      # if shortcircuiting is hit, we skip all other priorities...
      $pms->{shortcircuited} = 1;
      last;
    }

    my $timer = $self->{main}->time_method("tests_pri_".$priority);
    dbg("check: running tests for priority: $priority");

    # Here, we launch all the DNS RBL queries and let them run while we
    # inspect the message.  We try to launch all DNS queries at priority
    # -100, so one can shortcircuit tests at lower priority and not launch
    # unneeded DNS queries.
    if ($do_dns && !$rbls_running && $priority >= -100) {
      $rbls_running = 1;
      $pms->{async}->launch_queue(); # check if something was queued
      $self->run_rbl_eval_tests($pms);
      $self->{main}->call_plugins ("check_dnsbl", { permsgstatus => $pms });
    }

    $pms->harvest_completed_queries() if $rbls_running;
    # allow other, plugin-defined rule types to be called here
    $self->{main}->call_plugins ("check_rules_at_priority",
        { permsgstatus => $pms, priority => $priority, checkobj => $self });

    # do head tests
    $self->do_head_tests($pms, $priority);
    $pms->harvest_completed_queries() if $rbls_running;
    last if $pms->{deadline_exceeded} || $pms->{shortcircuited};

    $self->do_head_eval_tests($pms, $priority);
    $pms->harvest_completed_queries() if $rbls_running;
    last if $pms->{deadline_exceeded} || $pms->{shortcircuited};

    $self->do_body_tests($pms, $priority, $decoded);
    $pms->harvest_completed_queries() if $rbls_running;
    last if $pms->{deadline_exceeded} || $pms->{shortcircuited};

    $self->do_uri_tests($pms, $priority, $pms->get_uri_list());
    $pms->harvest_completed_queries() if $rbls_running;
    last if $pms->{deadline_exceeded} || $pms->{shortcircuited};

    $self->do_body_eval_tests($pms, $priority, $decoded);
    $pms->harvest_completed_queries() if $rbls_running;
    last if $pms->{deadline_exceeded} || $pms->{shortcircuited};
  
    $self->do_rawbody_tests($pms, $priority, $bodytext);
    $pms->harvest_completed_queries() if $rbls_running;
    last if $pms->{deadline_exceeded} || $pms->{shortcircuited};

    $self->do_rawbody_eval_tests($pms, $priority, $bodytext);
    $pms->harvest_completed_queries() if $rbls_running;
    last if $pms->{deadline_exceeded} || $pms->{shortcircuited};
  
    $self->do_full_tests($pms, $priority, \$fulltext);
    $pms->harvest_completed_queries() if $rbls_running;
    last if $pms->{deadline_exceeded} || $pms->{shortcircuited};

    $self->do_full_eval_tests($pms, $priority, \$fulltext);
    $pms->harvest_completed_queries() if $rbls_running;
    last if $pms->{deadline_exceeded} || $pms->{shortcircuited};

    # we may need to call this more often than once through the loop, but
    # it needs to be done at least once, either at the beginning or the end.
    $self->{main}->call_plugins ("check_tick", { permsgstatus => $pms });
    $pms->harvest_completed_queries() if $rbls_running;

    # check for ready metas
    $self->do_meta_tests($pms, $priority);
  }

  # Finish DNS results
  if ($do_dns) {
    $pms->harvest_dnsbl_queries();
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

  # last chance to handle left callbacks, make rule hits etc
  $self->{main}->call_plugins ("check_cleanup", { permsgstatus => $pms });

  # final check for ready metas
  $self->do_meta_tests($pms, undef, 1);

  # check dns_block_rule (bug 6728)
  # TODO No idea yet what would be the most logical place to do all these..
  if ($conf->{dns_block_rule}) {
    foreach my $rule (keys %{$conf->{dns_block_rule}}) {
      next if !$pms->{tests_already_hit}->{$rule}; # hit?
      foreach my $domain (keys %{$conf->{dns_block_rule}{$rule}}) {
        my $blockfile = $self->{main}->sed_path("__global_state_dir__/dnsblock_$domain");
        next if -f $blockfile; # no need to warn and create again..
        warn "check: dns_block_rule $rule hit, creating $blockfile ".
             "(This means DNSBL blocked you due to too many queries. ".
             "Set all affected rules score to 0, or use ".
             "\"dns_query_restriction deny $domain\" to disable queries)\n";
        Mail::SpamAssassin::Util::touch_file($blockfile, { create_exclusive => 1 });
      }
    }
  }

  # PMS cleanup will write reports etc, all rule hits must be registered by now
  $pms->check_cleanup();

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
    my $counters = $conf->{want_rebuild_for_type};
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

sub do_meta_tests {
  my ($self, $pms, $priority, $finish) = @_;

  return if $pms->{deadline_exceeded} || $pms->{shortcircuited};

  # Needed for Reuse to work, otherwise we don't care about priorities
  if (defined $priority && $self->{main}->have_plugin('start_rules')) {
    $self->{main}->call_plugins('start_rules', {
      permsgstatus => $pms,
      ruletype => 'meta',
      priority => $priority
    });
  }

  return if $self->{am_compiling}; # nothing to compile here
  return if !$finish && !$pms->{meta_check_ready}; # nothing to check

  my $mr = $pms->{meta_check_ready};
  my $mp = $pms->{meta_pending};
  my $md = $pms->{conf}->{meta_dependencies};
  my $mt = $pms->{conf}->{meta_tests};
  my $h = $pms->{tests_already_hit};
  my $retry;

  # When finishing, first mark all unrun non-meta rules as finished,
  # it will enable the next loop to finish everything properly
  if ($finish) {
    foreach my $rulename (keys %$mp) {
      foreach my $deprule (@{$md->{$rulename}||[]}) {
        if (!exists $mt->{$deprule}) {
          $h->{$deprule} ||= 0;
        }
      }
    }
  }

RULE:
  foreach my $rulename ($finish ? keys %$mp : keys %$mr) {
    # Meta is not ready if some dependency has not run yet
    foreach my $deprule (@{$md->{$rulename}||[]}) {
      if (!exists $h->{$deprule}) {
        next RULE;
      }
    }
    # Metasubs look like ($_[1]->{$rulename}||0) ...
    my $result = $mt->{$rulename}->($pms, $h);
    if ($result) {
      dbg("rules: ran meta rule $rulename ======> got hit ($result)");
      $pms->got_hit($rulename, '', ruletype => 'meta', value => $result);
    } else {
      dbg("rules-all: ran meta rule $rulename, no hit") if $would_log_rules_all;
      $pms->rule_ready($rulename, 1); # mark meta done
    }
    delete $mr->{$rulename};
    delete $mp->{$rulename};
    # Reiterate all metas again, in case some meta depended on us
    $retry = 1;
  }

  goto RULE if $retry--;

  delete $pms->{meta_check_ready};
}

###########################################################################

sub run_rbl_eval_tests {
  my ($self, $pms) = @_;

  while (my ($rulename, $test) = each %{$pms->{conf}->{rbl_evals}}) {
    my $score = $pms->{conf}->{scores}->{$rulename};
    next unless $score;

    my $function = $test->[0];
    if (!exists $pms->{conf}->{eval_plugins}->{$function}) {
      warn "rules: unknown eval '$function' for $rulename, ignoring RBL eval\n";
      $pms->{rule_errors}++;
      next;
    }

    my $result;
    eval {
      $result = $pms->$function($rulename, @{$test->[1]});  1;
    } or do {
      my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
      die "rules: $eval_stat\n"  if index($eval_stat, '__alarm__ignore__') >= 0;
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
    $pms->{shortcircuited} = 1;
    return;
  }

  my $ruletype = $opts{type};
  dbg("rules: running $ruletype tests; score so far=".$pms->{score});

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
        my $qrptr = $self->{conf}->{test_qrs};
        my $test_qr;
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
  my \%captures;
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
  $self->add_evalstr2(' sub '.$methodname.' { '.$methodbody.' } '."\n");
  push (@TEMPORARY_METHODS, $methodname);
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
    my ($self, $pms, $conf, $rulename, $pat, %opts) = @_;

    push @{$ordered{
            $conf->{test_opt_header}->{$rulename} .
            (!exists $conf->{test_opt_unset}->{$rulename} ? '' : "\t$rulename")
         }}, $rulename;

    return if ($opts{doing_user_rules} &&
            !$self->is_user_rule_sub($rulename.'_head_test'));

    my ($op, $op_infix);
    if (exists $conf->{test_opt_exists}->{$rulename}) {
      $op_infix = 0;
      $op = exists $conf->{test_opt_neg}->{$rulename} ? '!defined' : 'defined';
    }
    else {
      $op_infix = 1;
      $op = exists $conf->{test_opt_neg}->{$rulename} ? '!~' : '=~';
    }

    $testcode{$rulename} = [$op_infix, $op, $pat];
  },
    pre_loop_body => sub
  {
    my ($self, $pms, $conf, %opts) = @_;
    $self->push_evalstr_prefix($pms, '
      no warnings q(uninitialized);
      my $hval; my @harr;
    ');
  },
    post_loop_body => sub
  {
    my ($self, $pms, $conf, %opts) = @_;
    # setup the function to run the rules
    while(my($k,$v) = each %ordered) {
      my($hdrname, $def) = split(/\t/, $k, 2);
      # get() might already include newlines, join accordingly (Bug 8121)
      $self->push_evalstr_prefix($pms, '
        if (scalar(@harr = $self->get(q{'.$hdrname.'}))) {
          $hval = join($harr[0] =~ /\n\z/ ? "" : "\n", @harr);
        } else {
          $hval = '.(!defined($def) ? 'undef' :'$self->{conf}->{test_opt_unset}->{q{'.$def.'}}').'
        }
      ');
      foreach my $rulename (@{$v}) {
          my $tc_ref = $testcode{$rulename};
          my ($op_infix, $op, $pat);
          ($op_infix, $op, $pat) = @$tc_ref  if defined $tc_ref;

          my $posline = '';
          my $ifwhile = 'if';
          my $matchg = '';
          my $whlast = '';

          my $matching_string_unavailable = 0;
          my $expr;
          if (!$op_infix) {  # function or its negation
            $expr = $op . '($hval)';
            $matching_string_unavailable = 1;
          }
          else {  # infix operator
            if (($conf->{tflags}->{$rulename}||'') =~ /\bmultiple\b/) {
              $posline = 'pos $hval = 0; $hits = 0;';
              $ifwhile = 'while';
              $matchg = 'g';
              if ($conf->{tflags}->{$rulename} =~ /\bmaxhits=(\d+)\b/) {
                $whlast = 'last if ++$hits >= '.untaint_var($1).';';
              }
            }
            $expr = '$hval '.$op.' /$test_qr/'.$matchg.'op';
          }

          # Make sure rule is marked ready for meta rules
          $self->add_evalstr($pms, '
          if ($scoresptr->{q{'.$rulename.'}}) {
            '.($op_infix ? '$test_qr = $qrptr->{q{'.$rulename.'}};' : '').'
            '.($op_infix ? $self->capture_rules_replace($conf, $rulename) : '').'
              '.($would_log_rules_all ?
                'dbg("rules-all: running header rule %s", q{'.$rulename.'});' : '').'
              $self->rule_ready(q{'.$rulename.'}, 1);
              '.$posline.'
              '.$self->hash_line_for_rule($pms, $rulename).'
              '.$ifwhile.' ('.$expr.') {
                '.($op_infix ? $self->capture_plugin_code() : '').'
                $self->got_hit(q{'.$rulename.'}, "", ruletype => "header");
                '.$self->hit_rule_plugin_code($pms, $rulename, "header", "",
                                  $matching_string_unavailable).'
                '.$whlast.'
              }
              '.$self->ran_rule_plugin_code($rulename, "header").'
            '.($op_infix ? "}\n" : '').'
          }
          ');
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
    my $sub = '';
    if ($would_log_rules_all) {
      $sub .= '
      dbg("rules-all: running body rule %s", q{'.$rulename.'});
      ';
    }
    my $nosubject = ($conf->{tflags}->{$rulename}||'') =~ /\bnosubject\b/;
    if ($nosubject) {
      $sub .= '
      my $nosubj = 1;
      ';
    }
    if (($conf->{tflags}->{$rulename}||'') =~ /\bmultiple\b/)
    {
      # support multiple matches
      $loopid++;
      my ($max) = $conf->{tflags}->{$rulename} =~ /\bmaxhits=(\d+)\b/;
      $max = untaint_var($max);
      $sub .= '
      $hits = 0;
      body_'.$loopid.': foreach my $l (@_) {
      ';
      if ($nosubject) {
        $sub .= '
        if ($nosubj) { $nosubj = 0; next; }
        ';
      }
      $sub .= '
        pos $l = 0;
        '.$self->hash_line_for_rule($pms, $rulename).'
        while ($l =~ /$test_qr/gop) {
          '.$self->capture_plugin_code().'
          $self->got_hit(q{'.$rulename.'}, "BODY: ", ruletype => "body");
          '. $self->hit_rule_plugin_code($pms, $rulename, "body", "") . '
          '. ($max? 'last body_'.$loopid.' if ++$hits >= '.$max.';' : '') .'
        }
      }
      ';
    }
    else {
      # omitting the "pos" call, "body_loopid" label, use of while()
      # instead of if() etc., shaves off 8 perl OPs.
      $sub .= '
      foreach my $l (@_) {
      ';
      if ($nosubject) {
        $sub .= '
        if ($nosubj) { $nosubj = 0; next; }
        ';
      }
      $sub .= '
        '.$self->hash_line_for_rule($pms, $rulename).'
        if ($l =~ /$test_qr/op) {
          '.$self->capture_plugin_code().'
          $self->got_hit(q{'.$rulename.'}, "BODY: ", ruletype => "body");
          '. $self->hit_rule_plugin_code($pms, $rulename, "body", "last") .'
        }
      }
      ';
    }

    # Make sure rule is marked ready for meta rules
    $self->add_evalstr($pms, '
      if ($scoresptr->{q{'.$rulename.'}}) {
        $test_qr = $qrptr->{q{'.$rulename.'}};
        '.$self->capture_rules_replace($conf, $rulename).'
          $self->rule_ready(q{'.$rulename.'}, 1);
          '.$sub.'
          '.$self->ran_rule_plugin_code($rulename, "body").'
        }
      }
    ');

    return if ($opts{doing_user_rules} &&
            !$self->is_user_rule_sub($rulename.'_body_test'));
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
    my $sub = '';
    if ($would_log_rules_all) {
      $sub .= '
      dbg("rules-all: running uri rule %s", q{'.$rulename.'});
      ';
    }
    if (($conf->{tflags}->{$rulename}||'') =~ /\bmultiple\b/) {
      $loopid++;
      my ($max) = $conf->{tflags}->{$rulename} =~ /\bmaxhits=(\d+)\b/;
      $max = untaint_var($max);
      $sub .= '
      $hits = 0;
      uri_'.$loopid.': foreach my $l (@_) {
        pos $l = 0;
        '.$self->hash_line_for_rule($pms, $rulename).'
        while ($l =~ /$test_qr/gop) {
           '.$self->capture_plugin_code().'
           $self->got_hit(q{'.$rulename.'}, "URI: ", ruletype => "uri");
           '. $self->hit_rule_plugin_code($pms, $rulename, "uri", "") . '
           '. ($max? 'last uri_'.$loopid.' if ++$hits >= '.$max.';' : '') .'
        }
      }
      ';
    } else {
      $sub .= '
      foreach my $l (@_) {
        '.$self->hash_line_for_rule($pms, $rulename).'
          if ($l =~ /$test_qr/op) {
           '.$self->capture_plugin_code().'
           $self->got_hit(q{'.$rulename.'}, "URI: ", ruletype => "uri");
           '. $self->hit_rule_plugin_code($pms, $rulename, "uri", "last") .'
        }
      }
      ';
    }

    # Make sure rule is marked ready for meta rules
    $self->add_evalstr($pms, '
      if ($scoresptr->{q{'.$rulename.'}}) {
        $test_qr = $qrptr->{q{'.$rulename.'}};
        '.$self->capture_rules_replace($conf, $rulename).'
          $self->rule_ready(q{'.$rulename.'}, 1);
          '.$sub.'
          '.$self->ran_rule_plugin_code($rulename, "uri").'
        }
      }
    ');
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
    my $sub = '';
    if ($would_log_rules_all) {
      $sub .= '
      dbg("rules-all: running rawbody rule %s", q{'.$rulename.'});
      ';
    }
    if (($conf->{tflags}->{$rulename}||'') =~ /\bmultiple\b/)
    {
      # support multiple matches
      $loopid++;
      my ($max) = $conf->{tflags}->{$rulename} =~ /\bmaxhits=(\d+)\b/;
      $max = untaint_var($max);
      $sub .= '
      $hits = 0;
      rawbody_'.$loopid.': foreach my $l (@_) {
        pos $l = 0;
        '.$self->hash_line_for_rule($pms, $rulename).'
        while ($l =~ /$test_qr/gop) {
           '.$self->capture_plugin_code().'
           $self->got_hit(q{'.$rulename.'}, "RAW: ", ruletype => "rawbody");
           '. $self->hit_rule_plugin_code($pms, $rulename, "rawbody", "") . '
           '. ($max? 'last rawbody_'.$loopid.' if ++$hits >= '.$max.';' : '') .'
        }
      }
      ';
    }
    else {
      $sub .= '
      foreach my $l (@_) {
        '.$self->hash_line_for_rule($pms, $rulename).'
        if ($l =~ /$test_qr/op) {
           '.$self->capture_plugin_code().'
           $self->got_hit(q{'.$rulename.'}, "RAW: ", ruletype => "rawbody");
           '. $self->hit_rule_plugin_code($pms, $rulename, "rawbody", "last") . '
        }
      }
      ';
    }

    # Make sure rule is marked ready for meta rules
    $self->add_evalstr($pms, '
      if ($scoresptr->{q{'.$rulename.'}}) {
        $test_qr = $qrptr->{q{'.$rulename.'}};
        '.$self->capture_rules_replace($conf, $rulename).'
          $self->rule_ready(q{'.$rulename.'}, 1);
          '.$sub.'
          '.$self->ran_rule_plugin_code($rulename, "rawbody").'
        }
      }
    ');

    return if ($opts{doing_user_rules} &&
            !$self->is_user_rule_sub($rulename.'_rawbody_test'));
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
    my $whlast = 'last;';
    if (($conf->{tflags}->{$rulename}||'') =~ /\bmultiple\b/) {
      if (($conf->{tflags}->{$rulename}||'') =~ /\bmaxhits=(\d+)\b/) {
        $whlast = 'last if ++$hits >= '.untaint_var($1).';';
      } else {
        $whlast = '';
      }
    }
    # Make sure rule is marked ready for meta rules
    $self->add_evalstr($pms, '
      if ($scoresptr->{q{'.$rulename.'}}) {
        $test_qr = $qrptr->{q{'.$rulename.'}};
        '.$self->capture_rules_replace($conf, $rulename).'
          $self->rule_ready(q{'.$rulename.'}, 1);
          pos $$fullmsgref = 0;
          '.$self->hash_line_for_rule($pms, $rulename).'
          dbg("rules-all: running full rule %s", q{'.$rulename.'});
          $hits = 0;
          while ($$fullmsgref =~ /$test_qr/gp) {
            '.$self->capture_plugin_code().'
            $self->got_hit(q{'.$rulename.'}, "FULL: ", ruletype => "full");
            '. $self->hit_rule_plugin_code($pms, $rulename, "full", "last") . '
            '.$whlast.'
          }
          pos $$fullmsgref = 0;
          '.$self->ran_rule_plugin_code($rulename, "full").'
        }
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
			 'head_evals', '', $priority);
}

sub do_body_eval_tests {
  my ($self, $pms, $priority, $bodystring) = @_;
  return unless (defined($pms->{conf}->{body_evals}->{$priority}));
  dbg("rules: running body_eval tests; score so far=".$pms->{score});
  $self->run_eval_tests ($pms, $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS,
			 'body_evals', 'BODY: ', $priority, $bodystring);
}

sub do_rawbody_eval_tests {
  my ($self, $pms, $priority, $bodystring) = @_;
  return unless (defined($pms->{conf}->{rawbody_evals}->{$priority}));
  dbg("rules: running rawbody_eval tests; score so far=".$pms->{score});
  $self->run_eval_tests ($pms, $Mail::SpamAssassin::Conf::TYPE_RAWBODY_EVALS,
			 'rawbody_evals', 'RAW: ', $priority, $bodystring);
}

sub do_full_eval_tests {
  my ($self, $pms, $priority, $fullmsgref) = @_;
  return unless (defined($pms->{conf}->{full_evals}->{$priority}));
  dbg("rules: running full_eval tests; score so far=".$pms->{score});
  $self->run_eval_tests($pms, $Mail::SpamAssassin::Conf::TYPE_FULL_EVALS,
			'full_evals', '', $priority, $fullmsgref);
}

sub run_eval_tests {
  my ($self, $pms, $testtype, $evalname, $prepend2desc, $priority, @extraevalargs) = @_;
 
  my $master_deadline = $pms->{master_deadline};
  if ($pms->{deadline_exceeded}) {
    return;
  } elsif ($master_deadline && time > $master_deadline) {
    info("check: (run_eval) exceeded time limit, skipping further tests");
    $pms->{deadline_exceeded} = 1;
    return;
  } elsif ($self->{main}->call_plugins("have_shortcircuited",
                                        { permsgstatus => $pms })) {
    $pms->{shortcircuited} = 1;
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
    #dbg("rules: run_eval_tests - calling previously compiled %s", $method);
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
  my $evalhash = $conf->{$evalname}->{$priority};
  my $tflagsref = $conf->{tflags};
  my $scoresref = $conf->{scores};
  my $eval_pluginsref = $conf->{eval_plugins};
  my $have_ran_rule = $self->{main}->have_plugin("ran_rule");

  # the buffer for the evaluated code 
  my $evalstr = '';

  # conditionally include the dbg in the eval str
  my $dbgstr = '';
  if (would_log('dbg')) {
    $dbgstr = 'dbg("rules: ran eval rule $rulename ======> got hit ($result)");';
  }

  if ($self->{main}->have_plugin("start_rules")) {
    # XXX - should we use helper function here?
    $evalstr .= '
      $self->{main}->call_plugins("start_rules", {
              permsgstatus => $self,
              ruletype => "eval",
              priority => '.$priority.'
            });
';
  }

  while (my ($rulename, $test) = each %{$evalhash}) {
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
 
    # skip if score zeroed
    next if !$scoresref->{$rulename};

    my $function = untaint_var($test->[0]); # was validated with \w+
    if (!$function) {
      warn "rules: no eval function defined for $rulename\n";
      $pms->{rule_errors}++;
      next;
    }
 
    if (!exists $conf->{eval_plugins}->{$function}) {
      warn "rules: unknown eval '$function' for $rulename\n";
      $pms->{rule_errors}++;
      next;
    }

    $evalstr .= '
    if ($scoresptr->{q{'.$rulename.'}}) {
      $rulename = q#'.$rulename.'#;
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

    if ($would_log_rules_all) {
      $evalstr .= '
      dbg("rules-all: running eval rule %s (%s)", $rulename, q{'.$function.'});
      ';
    }

    $evalstr .= '
      eval {
        $result = $self->'.$function.'(@extraevalargs, @{$testptr->{$rulename}->[1]}); 1;
      } or do {
        $result = 0;
        die "rules: $@\n"  if index($@, "__alarm__ignore__") >= 0;
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

    # If eval returns undef, it means rule is running async and
    # will be marked ready later by rule_ready() or got_hit()
    $evalstr .= '
      if (defined $result) {
        if ($result) {
          $self->got_hit($rulename, $prepend2desc, ruletype => "eval", value => $result);
          '.$dbgstr.'
        } else {
          $self->rule_ready($rulename);
        }
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

    my \$testptr = \$self->{conf}->{$evalname}->{$priority};
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
    $pms->{rule_errors}++;
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
  # I have no idea why evals are being cluttered by "hashlines" ??
  # Nobody cares about source_file unless keep_config_parsing_metadata is set!
  # If you are debugging hanging rule, then simply uncomment this..
  #return "\ndbg(\"rules: will run %s\", q(".$rulename."));\n";
  return '' if !%{$pms->{conf}->{source_file}};
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

sub capture_plugin_code {
  my ($self) = @_;

  # Save named captures for regex template rules, tags will be set in
  # ran_rule_plugin_code to allow tflags multiple to save all
  return '
        if (%-) {
          foreach my $cname (keys %-) {
            push @{$captures{$cname}}, grep { $_ ne "" } @{$-{$cname}};
          }
        }
  ';
}

sub hit_rule_plugin_code {
  my ($self, $pms, $rulename, $ruletype, $loop_break_directive,
      $matching_string_unavailable) = @_;

  my $match;
  if ($matching_string_unavailable) {
    $match = '"<YES>"'; # nothing better to report, match is not set by this rule
  } else {
    # simple, but suffers from 'user data interpreted as a boolean', Bug 6360
    # ... which is fixed now with defined stanza
    $match = '(defined ${^MATCH} ? ${^MATCH} : "<negative match>")';
  }

  my $code = '';
  if (exists($pms->{should_log_rule_hits})) {
    $code .= '
        dbg("rules: ran '.$ruletype.' rule '.$rulename.' ======> got hit: \"" . '.
            $match.' . "\"");
    ';
  }

  if ($pms->{save_pattern_hits}) {
    $code .= '
        $self->{pattern_hits}->{q{'.$rulename.'}} = '.$match.';
    ';
  }

  # if we're not running "tflags multiple", break out of the matching
  # loop this way
  if ($loop_break_directive &&
      ($pms->{conf}->{tflags}->{$rulename}||'') !~ /\bmultiple\b/) {
    $code .= $loop_break_directive.';';
  }

  return $code;
}

sub ran_rule_plugin_code {
  my ($self, $rulename, $ruletype) = @_;

  # Set tags from captured values
  my $code = '
    if (%captures) {
      $self->set_captures(\%captures);
      %captures = ();
    }
  ';

  if ($self->{main}->have_plugin("ran_rule")) {
    $code .= '
    $self->{main}->call_plugins ("ran_rule", { permsgstatus => $self, rulename => \''.$rulename.'\', ruletype => \''.$ruletype.'\' });
    ';
  }

  return $code;
}

sub capture_rules_replace {
  my ($self, $conf, $rulename) = @_;

  return '{' unless exists $conf->{capture_template_rules}->{$rulename};

  # Replace all named capture templates in regex, format %{CAPTURE_NAME}
  # Note that backquotes must be double escaped in $test_qr
  my $code = '
      foreach my $cname (keys %{$self->{conf}->{capture_template_rules}->{q{'.$rulename.'}}}) {
        my $valref = $self->get_tag_raw($cname);
        my @vals = grep { defined $_ && $_ ne "" } (ref $valref ? @$valref : $valref);
        if (@vals) {
          my $cval = "(?:".join("|", map { quotemeta($_) } @vals).")";
          $test_qr =~ s/(?<!\\\\)\\%\\\\\\{\Q${cname}\E\\\\\\}/$cval/gs;
  ';
  if ($would_log_rules_all) {
    $code .= '
          dbg("rules-all: replaced regex capture template: %s, %s, %s",
            q{'.$rulename.'}, $cname, $test_qr);
    ';
  }
  $code .= '
        } else {
  ';
  if ($would_log_rules_all) {
    $code .= '
          dbg("rules-all: not running rule %s, dependent tag not defined: %s",
            q{'.$rulename.'}, $cname);
    ';
  }
  $code .= '
          $test_qr = undef;
          last;
        }
      }
      if ($test_qr) {
  ';

  return $code;
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

sub compile_now_start {
  my ($self, $params) = @_;
  $self->{am_compiling} = 1;
}

sub compile_now_finish {
  my ($self, $params) = @_;
  delete $self->{am_compiling};
}

###########################################################################

1;
