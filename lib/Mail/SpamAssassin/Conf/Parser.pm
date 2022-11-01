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

Mail::SpamAssassin::Conf::Parser - parse SpamAssassin configuration

=head1 SYNOPSIS

  (see Mail::SpamAssassin)

=head1 DESCRIPTION

Mail::SpamAssassin is a module to identify spam using text analysis and
several internet-based realtime blocklists.

This class is used internally by SpamAssassin to parse its configuration files.
Please refer to the C<Mail::SpamAssassin> documentation for public interfaces.

=head1 STRUCTURE OF A CONFIG BLOCK

This is the structure of a config-setting block.  Each is a hashref which may
contain these keys:

=over 4

=item setting

the name of the setting it modifies, e.g. "required_score". this also doubles
as the default for 'command' (below). THIS IS REQUIRED.

=item command

The command string used in the config file for this setting.  Optional;
'setting' will be used for the command if this is omitted.

=item aliases

An [aryref] of other aliases for the same command.  optional.

=item type

The type of this setting:

 - $CONF_TYPE_NOARGS: must not have any argument, like "clear_headers"
 - $CONF_TYPE_STRING: string
 - $CONF_TYPE_NUMERIC: numeric value (float or int)
 - $CONF_TYPE_BOOL: boolean (0/no or 1/yes)
 - $CONF_TYPE_TEMPLATE: template, like "report"
 - $CONF_TYPE_ADDRLIST: list of mail addresses, like "welcomelist_from"
 - $CONF_TYPE_HASH_KEY_VALUE: hash key/value pair, like "describe" or tflags
 - $CONF_TYPE_STRINGLIST list of strings, stored as an array
 - $CONF_TYPE_IPADDRLIST list of IP addresses, stored as an array of SA::NetSet
 - $CONF_TYPE_DURATION a nonnegative time interval in seconds - a numeric value
                      (float or int), optionally suffixed by a time unit (s, m,
                      h, d, w), seconds are implied if unit is missing

If this is set, and a 'code' block does not already exist, a 'code' block is
assigned based on the type.

In addition, the SpamAssassin test suite will validate that the settings
do not 'leak' between users.

Note that C<$CONF_TYPE_HASH_KEY_VALUE>-type settings require that the
value be non-empty, otherwise they'll produce a warning message.

=item code

A subroutine to deal with the setting.  ONE OF B<code> OR B<type> IS REQUIRED.
The arguments passed to the function are C<($self, $key, $value, $line)>,
where $key is the setting (*not* the command), $value is the value string,
and $line is the entire line.

There are two special return values that the B<code> subroutine may return
to signal that there is an error in the configuration:

C<$Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE> -- this setting requires
that a value be set, but one was not provided.

C<$Mail::SpamAssassin::Conf::INVALID_VALUE> -- this setting requires a value
from a set of 'valid' values, but the user provided an invalid one.

C<$Mail::SpamAssassin::Conf::INVALID_HEADER_FIELD_NAME> -- this setting
requires a syntactically valid header field name, but the user provided
an invalid one.

Any other values -- including C<undef> -- returned from the subroutine are
considered to mean 'success'.

It is good practice to set a 'type', if possible, describing how your settings
are stored on the Conf object; this allows the SpamAssassin test suite to
validate that the settings do not 'leak' between users.

=item default

The default value for the setting.  may be omitted if the default value is a
non-scalar type, which should be set in the Conf ctor.  note for path types:
using "__userstate__" is recommended for defaults, as it allows
Mail::SpamAssassin module users who set that configuration setting, to receive
the correct values.

=item is_priv

Set to 1 if this setting requires 'allow_user_rules' when run from spamd.

=item is_admin

Set to 1 if this setting can only be set in the system-wide config when run
from spamd.  (All settings can be used by local programs run directly by the
user.)

=back

=cut

package Mail::SpamAssassin::Conf::Parser;

use Mail::SpamAssassin::Conf;
use Mail::SpamAssassin::Constants qw(:sa);
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Util qw(untaint_var compile_regexp);
use Mail::SpamAssassin::NetSet;

use strict;
use warnings;
# use bytes;
use re 'taint';

our @ISA = qw();

my $ARITH_EXPRESSION_LEXER = ARITH_EXPRESSION_LEXER;
my $META_RULES_MATCHING_RE = META_RULES_MATCHING_RE;

###########################################################################

sub new {
  my $class = shift;
  $class = ref($class) || $class;
  my ($conf) = @_;

  my $self = {
    'conf'      => $conf
  };

  $self->{command_luts} = { };

  bless ($self, $class);
  $self;
}

###########################################################################

sub register_commands {
  my($self, $arrref) = @_;
  my $conf = $self->{conf};

  $self->set_defaults_from_command_list($arrref);
  $self->build_command_luts($arrref);
  push(@{$conf->{registered_commands}}, @{$arrref});
}

sub set_defaults_from_command_list {
  my ($self, $arrref) = @_;
  my $conf = $self->{conf};
  foreach my $cmd (@{$arrref}) {
    # note! exists, not defined -- we want to be able to set
    # "undef" default values.
    if (exists($cmd->{default})) {
      $conf->{$cmd->{setting}} = $cmd->{default};
    }
  }
}

sub build_command_luts {
  my ($self, $arrref) = @_;

  my $conf = $self->{conf};

  foreach my $cmd (@{$arrref}) {
    my $cmdname = $cmd->{command} || $cmd->{setting};
    $self->{command_luts}->{$cmdname} = $cmd;

    if ($cmd->{aliases} && scalar @{$cmd->{aliases}} > 0) {
      foreach my $name (@{$cmd->{aliases}}) {
        $self->{command_luts}->{$name} = $cmd;
      }
    }
  }
}

###########################################################################

sub parse {
  my ($self, undef, $scoresonly) = @_; # leave $rules in $_[1]

  my $conf = $self->{conf};
  $self->{scoresonly} = $scoresonly;

  # Language selection:
  # See http://www.gnu.org/manual/glibc-2.2.5/html_node/Locale-Categories.html
  # and http://www.gnu.org/manual/glibc-2.2.5/html_node/Using-gettextized-software.html
  my $lang = $ENV{'LANGUAGE'}; # LANGUAGE has the highest precedence but has a
  if ($lang) {                 # special format: The user may specify more than
    $lang =~ s/:.*$//;         # one language here, colon separated. We use the
  }                            # first one only (lazy bums we are :o)
  $lang ||= $ENV{'LC_ALL'};
  $lang ||= $ENV{'LC_MESSAGES'};
  $lang ||= $ENV{'LANG'};
  $lang ||= 'C';               # Nothing set means C/POSIX

  if ($lang =~ /^(C|POSIX)$/) {
    $lang = 'en_US';           # Our default language
  } else {
    $lang =~ s/[@.+,].*$//;    # Strip codeset, modifier/audience, etc.
  }                            # (eg. .utf8 or @euro)

  # get fast-access handles on the command lookup tables
  my $lut = $self->{command_luts};
  my %migrated_keys = map { $_ => 1 }
            @Mail::SpamAssassin::Conf::MIGRATED_SETTINGS;

  $self->{currentfile} = '(no file)';
  $self->{linenum} = ();
  my $skip_parsing = 0;
  my @curfile_stack;
  my @if_stack;
  my @conf_lines = split (/\n/, $_[1]);
  my $line;
  $self->{if_stack} = \@if_stack;
  $self->{cond_cache} = { };
  $self->{file_scoped_attrs} = { };

  my $keepmetadata = $conf->{main}->{keep_config_parsing_metadata};

  while (defined ($line = shift @conf_lines)) {
    local ($1);         # bug 3838: prevent random taint flagging of $1
    my $parse_error;    # undef by default, may be overridden

    # don't count internal file start/end lines
    $self->{linenum}{$self->{currentfile}}++ if index($line, 'file ') != 0;

    if (index($line,'#') > -1) {
      # bug 5545: used to support testing rules in the ruleqa system
      if ($keepmetadata && $line =~ /^\#testrules/) {
        $self->{file_scoped_attrs}->{testrules}++;
        next;
      }

      # bug 6800: let X-Spam-Checker-Version also show what sa-update we are at
      if (index($line, '# UPD') == 0 && $line =~ /^\# UPDATE version (\d+)$/) {
        for ($self->{currentfile}) {  # just aliasing, not a loop
          $conf->{update_version}{$_} = $1  if defined $_ && $_ ne '(no file)';
        }
      }

      $line =~ s/(?<!\\)#.*$//; # remove comments
      $line =~ s/\\#/#/g; # hash chars are escaped, so unescape them
    }

    $line =~ s/^\s+//;  # remove leading whitespace
    $line =~ s/\s+$//;  # remove tailing whitespace
    next unless($line); # skip empty lines

    # handle i18n
    if (index($line, 'lang') == 0 && $line =~ s/^lang\s+(\S+)\s+//) {
      next if $lang !~ /^$1/i;
    }

    my($key, $value) = split(/\s+/, $line, 2);
    $key = lc $key;
    # convert all dashes in setting name to underscores.
    $key =~ tr/-/_/;
    $value = '' unless defined($value);

    # $key if/elsif blocks sorted by most commonly used
    if ($key eq 'endif') {
      if ($value ne '') {
        $parse_error = "config: '$key' must be standalone";
        goto failed_line;
      }
      my $lastcond = pop @if_stack;
      if (!defined $lastcond) {
        $parse_error = "config: missing starting 'if' for '$key'";
        goto failed_line;
      }
      $skip_parsing = $lastcond->{skip_parsing};
      next;
    }
    elsif ($key eq 'ifplugin') {
      if ($value eq '') {
        $parse_error = "config: missing '$key' condition";
        goto failed_line;
      }
      $self->handle_conditional ($key, "plugin ($value)",
                        \@if_stack, \$skip_parsing);
      next;
    }
    elsif ($key eq 'if') {
      if ($value eq '') {
        $parse_error = "config: missing '$key' condition";
        goto failed_line;
      }
      $self->handle_conditional ($key, $value,
                        \@if_stack, \$skip_parsing);
      next;
    }
    elsif ($key eq 'file') {
      if ($value =~ /^start\s+(.+)$/) {
        dbg("config: parsing file $1");
        push (@curfile_stack, $self->{currentfile});
        $self->{currentfile} = $1;
        next;
      }
      elsif ($value =~ /^end\s/) {
        foreach (@if_stack) {
          my $msg = "config: unclosed '$_->{type}' found ".
                    "in $self->{currentfile} (line $_->{linenum})";
          $self->lint_warn($msg, undef);
        }
        $self->{file_scoped_attrs} = { };
        @if_stack = ();
        $skip_parsing = 0;
        $self->{currentfile} = pop @curfile_stack;
        next;
      }
      else {
        $parse_error = "config: missing '$key' value";
        goto failed_line;
      }
    }
    elsif ($key eq 'include') {
      if ($value eq '') {
        $parse_error = "config: missing '$key' value";
        goto failed_line;
      }
      $value = $self->fix_path_relative_to_current_file($value);
      my $text = $conf->{main}->read_cf($value, 'included file');
      unshift (@conf_lines,
          "file end $self->{currentfile}",
          split (/\n/, $text),
          "file start $self->{currentfile}");
      next;
    }
    elsif ($key eq 'else') {
      if ($value ne '') {
        $parse_error = "config: '$key' must be standalone";
        goto failed_line;
      }

      # TODO: if/else/else won't get flagged here :(
      if (!@if_stack) {
        $parse_error = "config: '$key' missing starting if";
        goto failed_line;
      }

      # Check if we are blocked anywhere in previous if-stack (Bug 7848)
      if (grep { $_->{skip_parsing} } @if_stack) {
        $skip_parsing = 1;
      } else {
        $skip_parsing = !$skip_parsing;
      }

      next;
    }

    # preprocessing? skip all other commands
    next if $skip_parsing;

    if ($key eq 'require_version') {
      if ($value eq '') {
        $parse_error = "config: missing '$key' value";
        goto failed_line;
      }

      # if it wasn't replaced during install, assume current version ...
      next if ($value eq "\@\@VERSION\@\@");

      my $ver = $Mail::SpamAssassin::VERSION;

      # if we want to allow "require_version 3.0" be good for all
      # "3.0.x" versions:
      ## make sure it's a numeric value
      #$value += 0.0;
      ## convert 3.000000 -> 3.0, stay backward compatible ...
      #$ver =~ s/^(\d+)\.(\d{1,3}).*$/sprintf "%d.%d", $1, $2/e;
      #$value =~ s/^(\d+)\.(\d{1,3}).*$/sprintf "%d.%d", $1, $2/e;

      if ($ver ne $value) {
        my $msg = "config: configuration file '$self->{currentfile}' requires ".
                "version $value of SpamAssassin, but this is code version ".
                "$ver. Maybe you need to use ".
                "the -C switch, or remove the old config files? ".
                "Skipping this file.";
        warn $msg;
        $self->lint_warn($msg, undef);
        $skip_parsing = 1;
      }
      next;
    }

    my $cmd = $lut->{$key};

    # we've either fallen through with no match, in which case this
    # if() will fail, or we have a match.
    if ($cmd) {
      if ($self->{scoresonly}) {              # reading user config from spamd
        if ($cmd->{is_priv} && !$conf->{allow_user_rules}) {
          info("config: not parsing, 'allow_user_rules' is 0: $line");
          goto failed_line;
        }
        if ($cmd->{is_admin}) {
          info("config: not parsing, administrator setting: $line");
          goto failed_line;
        }
      }

      if (!$cmd->{code}) {
        if (! $self->setup_default_code_cb($cmd)) {
          goto failed_line;
        }
      }

      my $ret = &{$cmd->{code}} ($conf, $cmd->{setting}, $value, $line);
      next if !$ret;

      if ($ret eq $Mail::SpamAssassin::Conf::INVALID_VALUE) {
        $parse_error = "config: invalid '$key' value";
        goto failed_line;
      }
      elsif ($ret eq $Mail::SpamAssassin::Conf::INVALID_HEADER_FIELD_NAME) {
        $parse_error = "config: invalid header field name";
        goto failed_line;
      }
      elsif ($ret eq $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE) {
        $parse_error = "config: missing '$key' value";
        goto failed_line;
      }
      else {
        next;
      }
    }

    # last ditch: try to see if the plugins know what to do with it
    if ($conf->{main}->call_plugins("parse_config", {
                key => $key,
                value => $value,
                line => $line,
                conf => $conf,
                user_config => $self->{scoresonly}
            }))
    {
      # a plugin dealt with it successfully.
      next;
    }

failed_line:
    my $msg = $parse_error;
    my $is_error = 1;
    if (!$msg) {
      # use a default warning, if a more specific one wasn't output
      if ($migrated_keys{$key}) {
        # this key was moved into a plugin; non-fatal for lint
        $is_error = 0;
        $msg = "config: failed to parse line, now a plugin";
      } else {
        # a real syntax error; this is fatal for --lint
        $msg = "config: failed to parse line";
      }
    }

    if ($self->{currentfile} eq '(no file)') {
      $msg .= " in $self->{currentfile}: $line"; 
    } else {
      $msg .= " in $self->{currentfile} ".
              "(line $self->{linenum}{$self->{currentfile}}): $line"; 
    }
    $self->lint_warn($msg, undef, $is_error);
  }

  delete $self->{if_stack};
  delete $self->{cond_cache};
  delete $self->{linenum};

  $self->lint_check();
  $self->fix_tests();

  delete $self->{scoresonly};
}

sub handle_conditional {
  my ($self, $key, $value, $if_stack_ref, $skip_parsing_ref) = @_;
  my $conf = $self->{conf};

  # If we have already successfully evaled the $value,
  # just do what we would do then
  if (exists $self->{cond_cache}{"$key $value"}) {
    push (@{$if_stack_ref}, {
        'type' => $key,
        'conditional' => $value,
        'skip_parsing' => $$skip_parsing_ref,
        'linenum' => $self->{linenum}{$self->{currentfile}}
      });
    if ($self->{cond_cache}{"$key $value"} == 0) {
      $$skip_parsing_ref = 1;
    }
    return;
  }

  my @tokens = ($value =~ /($ARITH_EXPRESSION_LEXER)/og);
  my $eval = '';

  foreach my $token (@tokens) {
    if ($token eq '(' || $token eq ')' || $token eq '!') {
      # using tainted subr. argument may taint the whole expression, avoid
      my $u = untaint_var($token);
      $eval .= $u . " ";
    }
    elsif ($token eq 'plugin') {
      # replace with a method call
      $eval .= '$self->cond_clause_plugin_loaded';
    }
    elsif ($token eq 'can') {
      # replace with a method call
      $eval .= '$self->cond_clause_can';
    }
    elsif ($token eq 'has') {
      # replace with a method call
      $eval .= '$self->cond_clause_has';
    }	
    elsif ($token eq 'version') {
      $eval .= $Mail::SpamAssassin::VERSION." ";
    }
    elsif ($token eq 'perl_version') {
      $eval .= $]." ";
    }
    elsif ($token eq 'local_tests_only') {
      $eval .= '($self->{conf}->{main}->{local_tests_only}?1:0) '
    }
    elsif ($token =~ /^(?:\W{1,5}|[+-]?\d+(?:\.\d+)?)$/) {
      # using tainted subr. argument may taint the whole expression, avoid
      my $u = untaint_var($token);
      $eval .= $u . " ";
    }
    elsif ($token =~ /^\w[\w\:]+$/) { # class name
      # Strictly controlled form:
      if ($token =~ /^(?:\w+::){0,10}\w+$/) {
        # trunk Dmarc.pm was renamed to DMARC.pm
        # (same check also in Conf.pm loadplugin)
        if ($token eq 'Mail::SpamAssassin::Plugin::Dmarc') {
          $token = 'Mail::SpamAssassin::Plugin::DMARC';
        }
        # backwards compatible - removed in 4.1
        # (same check also in Conf.pm loadplugin)
        elsif ($token eq 'Mail::SpamAssassin::Plugin::WhiteListSubject') {
          $token = 'Mail::SpamAssassin::Plugin::WelcomeListSubject';
        }
        my $u = untaint_var($token);
        $eval .= "'$u'";
      } else {
        my $msg = "config: not allowed value '$token' ".
            "in $self->{currentfile} (line $self->{linenum}{$self->{currentfile}})";
        $self->lint_warn($msg, undef);
        return;
      }
    }
    else {
      my $msg = "config: unparseable value '$token' ".
          "in $self->{currentfile} (line $self->{linenum}{$self->{currentfile}})";
      $self->lint_warn($msg, undef);
      return;
    }
  }

  push (@{$if_stack_ref}, {
      'type' => $key,
      'conditional' => $value,
      'skip_parsing' => $$skip_parsing_ref,
      'linenum' => $self->{linenum}{$self->{currentfile}}
    });

  if (eval $eval) {
    $self->{cond_cache}{"$key $value"} = 1;
    # leave $skip_parsing as-is; we may not be parsing anyway in this block.
    # in other words, support nested 'if's and 'require_version's
  } else {
    if ($@) {
      my $msg = "config: error parsing conditional ".
          "in $self->{currentfile} (line $self->{linenum}{$self->{currentfile}}): $eval ($@)";
      warn $msg;
      $self->lint_warn($msg, undef, 0); # not fatal?
    }
    $self->{cond_cache}{"$key $value"} = 0;
    $$skip_parsing_ref = 1;
  }
}

# functions supported in the "if" eval:
sub cond_clause_plugin_loaded {
  return 1 if $_[1] eq 'Mail::SpamAssassin::Plugin::RaciallyCharged'; # removed in 4.1
  return $_[0]->{conf}->{plugins_loaded}->{$_[1]};
}

sub cond_clause_can {
  my ($self, $method) = @_;
  if ($self->{currentfile} =~ q!\buser_prefs$! ) {
    warn "config: 'if can $method' not available in user_prefs";
    return 0
  }
  $self->cond_clause_can_or_has('can', $method);
}

sub cond_clause_has {
  my ($self, $method) = @_;
  $self->cond_clause_can_or_has('has', $method);
}

sub cond_clause_can_or_has {
  my ($self, $fn_name, $method) = @_;

  local($1,$2);
  if (!defined $method) {
    my $msg = "config: bad 'if' line, no argument to $fn_name() ".
              "in $self->{currentfile} (line $self->{linenum}{$self->{currentfile}})";
    $self->lint_warn($msg, undef);
  } elsif ($method =~ /^(.*)::([^:]+)$/) {
    no strict "refs";
    my($module, $meth) = ($1, $2);
    return 1  if $module->can($meth) &&
                 ( $fn_name eq 'has' || &{$method}() );
  } else {
    my $msg = "config: bad 'if' line, cannot find '::' in $fn_name($method) ".
              "in $self->{currentfile} (line $self->{linenum}{$self->{currentfile}})";
    $self->lint_warn($msg, undef);
  }
  return;
}

# Let's do some linting here ...
# This is called from _parse(), BTW, so we can check for $conf->{tests}
# easily before finish_parsing() is called and deletes it.
#
sub lint_check {
  my ($self) = @_;
  my $conf = $self->{conf};

  if ($conf->{lint_rules}) {
    # Check for description and score issues in lint fashion
    while ( my $k = each %{$conf->{descriptions}} ) {
      if (!exists $conf->{tests}->{$k}) {
        dbg("config: description exists for non-existent rule $k");
      }
    }

    while ( my($sk) = each %{$conf->{scores}} ) {
      if (!exists $conf->{tests}->{$sk}) {
        # bug 5514: not a lint warning any more
        dbg("config: score set for non-existent rule $sk");
      }
    }
  }
}

# Iterate through tests and check/fix things
sub fix_tests {
  my ($self) = @_;

  my $conf = $self->{conf};
  my $would_log_dbg = would_log('dbg');

  while ( my $k = each %{$conf->{tests}} ) {
    # we should set a default score for all valid rules...  Do this here
    # instead of add_test because mostly 'score' occurs after the rule is
    # specified, so why set the scores to default, then set them again at
    # 'score'?
    # 
    if ( ! exists $conf->{scores}->{$k} ) {
      # T_ rules (in a testing probationary period) get low, low scores
      my $set_score = index($k, 'T_') == 0 ? 0.01 : 1.0;

      $set_score = -$set_score if ( ($conf->{tflags}->{$k}||'') =~ /\bnice\b/ );
      for my $index (0..3) {
        $conf->{scoreset}->[$index]->{$k} = $set_score;
      }
    }

    # loop through all the tests and if we are missing a description with debug
    # set, throw a note except for testing T_ or meta __ rules.
    if ($would_log_dbg && $k !~ m/^(?:T_|__)/i) {
      if ( ! exists $conf->{descriptions}->{$k} ) {
        dbg("config: no description set for rule $k");
      }
    }
  }
}

###########################################################################

sub setup_default_code_cb {
  my ($self, $cmd) = @_;
  my $type = $cmd->{type};

  if ($type == $Mail::SpamAssassin::Conf::CONF_TYPE_STRING) {
    $cmd->{code} = \&set_string_value;
  }
  elsif ($type == $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL) {
    $cmd->{code} = \&set_bool_value;
  }
  elsif ($type == $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC) {
    $cmd->{code} = \&set_numeric_value;
  }
  elsif ($type == $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE) {
    $cmd->{code} = \&set_hash_key_value;
  }
  elsif ($type == $Mail::SpamAssassin::Conf::CONF_TYPE_ADDRLIST) {
    $cmd->{code} = \&set_addrlist_value;
  }
  elsif ($type == $Mail::SpamAssassin::Conf::CONF_TYPE_TEMPLATE) {
    $cmd->{code} = \&set_template_append;
  }
  elsif ($type == $Mail::SpamAssassin::Conf::CONF_TYPE_NOARGS) {
    $cmd->{code} = \&set_no_value;
  }
  elsif ($type == $Mail::SpamAssassin::Conf::CONF_TYPE_STRINGLIST) {
    $cmd->{code} = \&set_string_list;
  }
  elsif ($type == $Mail::SpamAssassin::Conf::CONF_TYPE_IPADDRLIST) {
    $cmd->{code} = \&set_ipaddr_list;
  }
  elsif ($type == $Mail::SpamAssassin::Conf::CONF_TYPE_DURATION) {
    $cmd->{code} = \&set_duration_value;
  }
  else {
    warn "config: unknown conf type $type!";
    return 0;
  }
  return 1;
}

sub set_no_value {
  my ($conf, $key, $value, $line) = @_;

  unless (!defined $value || $value eq '') {
    return $Mail::SpamAssassin::Conf::INVALID_VALUE;
  }
}

sub set_numeric_value {
  my ($conf, $key, $value, $line) = @_;

  unless (defined $value && $value !~ /^$/) {
    return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
  }
  unless ($value =~ /^ [+-]? \d+ (?: \. \d* )? \z/sx) {
    return $Mail::SpamAssassin::Conf::INVALID_VALUE;
  }
  # it is safe to untaint now that we know the syntax is a valid number
  $conf->{$key} = untaint_var($value) + 0;
}

sub set_duration_value {
  my ($conf, $key, $value, $line) = @_;

  local ($1,$2);
  unless (defined $value && $value !~ /^$/) {
    return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
  }
  unless ($value =~ /^( \+? \d+ (?: \. \d* )? ) (?: \s* ([smhdw]))? \z/sxi) {
    return $Mail::SpamAssassin::Conf::INVALID_VALUE;
  }
  $value = $1;
  $value *= { s => 1, m => 60, h => 3600,
              d => 24*3600, w => 7*24*3600 }->{lc $2}  if defined $2;
  # it is safe to untaint now that we know the syntax is a valid time interval
  $conf->{$key} = untaint_var($value) + 0;
}

sub set_bool_value {
  my ($conf, $key, $value, $line) = @_;

  unless (defined $value && $value !~ /^$/) {
    return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
  }

  # bug 4462: allow yes/1 and no/0 for boolean values
  $value = lc $value;
  if ($value eq 'yes' || $value eq '1') {
    $value = 1;
  }
  elsif ($value eq 'no' || $value eq '0') {
    $value = 0;
  }
  else {
    return $Mail::SpamAssassin::Conf::INVALID_VALUE;
  }

  $conf->{$key} = $value;
}

sub set_string_value {
  my ($conf, $key, $value, $line) = @_;

  unless (defined $value && $value !~ /^$/) {
    return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
  }

  $conf->{$key} = $value;  # keep tainted
}

sub set_string_list {
  my ($conf, $key, $value, $line) = @_;

  unless (defined $value && $value !~ /^$/) {
    return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
  }

  push(@{$conf->{$key}}, split(/\s+/, $value));
}

sub set_ipaddr_list {
  my ($conf, $key, $value, $line) = @_;

  unless (defined $value && $value !~ /^$/) {
    return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
  }

  foreach my $net (split(/\s+/, $value)) {
    $conf->{$key}->add_cidr($net);
  }
  $conf->{$key.'_configured'} = 1;
}

sub set_hash_key_value {
  my ($conf, $key, $value, $line) = @_;
  my($k,$v) = split(/\s+/, $value, 2);

  unless (defined $v && $v ne '') {
    return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
  }

  $conf->{$key}->{$k} = $v;  # keep tainted
}

sub set_addrlist_value {
  my ($conf, $key, $value, $line) = @_;

  unless (defined $value && $value !~ /^$/) {
    return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
  }
  $conf->{parser}->add_to_addrlist ($key, split(/\s+/, $value));  # keep tainted
}

sub remove_addrlist_value {
  my ($conf, $key, $value, $line) = @_;

  unless (defined $value && $value !~ /^$/) {
    return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
  }
  $conf->{parser}->remove_from_addrlist ($key, split(/\s+/, $value));
}

sub set_template_append {
  my ($conf, $key, $value, $line) = @_;
  if ( $value =~ /^"(.*?)"$/ ) { $value = $1; }
  $conf->{$key} .= $value."\n";  # keep tainted
}

sub set_template_clear {
  my ($conf, $key, $value, $line) = @_;
  unless (!defined $value || $value eq '') {
    return $Mail::SpamAssassin::Conf::INVALID_VALUE;
  }
  $conf->{$key} = '';
}

###########################################################################

sub finish_parsing {
  my ($self, $isuserconf) = @_;
  my $conf = $self->{conf};

  # note: this function is called once for system-wide configuration
  # with $isuserconf set to 0, then again for user conf with $isuserconf set to 1.
  if (!$isuserconf) {
    $conf->{main}->call_plugins("finish_parsing_start", { conf => $conf });
  } else {
    $conf->{main}->call_plugins("user_conf_parsing_start", { conf => $conf });
  }

  # compile meta rules
  $self->compile_meta_rules();
  $self->fix_priorities();
  $self->fix_tflags();

  dbg("config: finish parsing");

  while (my ($name, $text) = each %{$conf->{tests}}) {
    my $type = $conf->{test_types}->{$name};

    # Adjust priority -100 for net rules instead of default 0
    my $priority = $conf->{priority}->{$name} ? $conf->{priority}->{$name} :
        ($conf->{tflags}->{$name}||'') =~ /\bnet\b/ ? -100 : 0;
    $conf->{priorities}->{$priority}++;

    # eval type handling
    if (($type & 1) == 1) {
      if (my ($function, $args) = ($text =~ /^(\w+)\((.*?)\)$/)) {
        my $argsref = $self->pack_eval_args($args);
        if (!defined $argsref) {
          $self->lint_warn("syntax error for eval function $name: $text");
          next;
        }

        # Validate type
        my $expected_type = $conf->{eval_plugins_types}->{$function};
        if (defined $expected_type && $expected_type != $type) {
          # Allow both body and rawbody if expecting body
          if (!($expected_type == $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS &&
              $type == $Mail::SpamAssassin::Conf::TYPE_RAWBODY_EVALS))
          {
            my $estr = $Mail::SpamAssassin::Conf::TYPE_AS_STRING{$expected_type};
            $self->lint_warn("wrong rule type defined for $name, expected '$estr'");
            next;
          }
        }

        if ($type == $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS) {
          $conf->{body_evals}->{$priority}->{$name} = [ $function, [@$argsref] ];
        }
        elsif ($type == $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS) {
          $conf->{head_evals}->{$priority}->{$name} = [ $function, [@$argsref] ];
        }
        elsif ($type == $Mail::SpamAssassin::Conf::TYPE_RBL_EVALS) {
          # We don't do priorities for $Mail::SpamAssassin::Conf::TYPE_RBL_EVALS
          # we also use the arrayref instead of the packed string
          $conf->{rbl_evals}->{$name} = [ $function, [@$argsref] ];
        }
        elsif ($type == $Mail::SpamAssassin::Conf::TYPE_RAWBODY_EVALS) {
          $conf->{rawbody_evals}->{$priority}->{$name} = [ $function, [@$argsref] ];
        }
        elsif ($type == $Mail::SpamAssassin::Conf::TYPE_FULL_EVALS) {
          $conf->{full_evals}->{$priority}->{$name} = [ $function, [@$argsref] ];
        }
        #elsif ($type == $Mail::SpamAssassin::Conf::TYPE_URI_EVALS) {
        #  $conf->{uri_evals}->{$priority}->{$name} = [ $function, [@$argsref] ];
        #}
        else {
          $self->lint_warn("unknown type $type for $name: $text", $name);
          next;
        }
      }
      else {
        $self->lint_warn("syntax error for eval function $name: $text", $name);
        next;
      }
    }
    # non-eval tests
    else {
      if ($type == $Mail::SpamAssassin::Conf::TYPE_BODY_TESTS) {
        $conf->{body_tests}->{$priority}->{$name} = $text;
      }
      elsif ($type == $Mail::SpamAssassin::Conf::TYPE_HEAD_TESTS) {
        $conf->{head_tests}->{$priority}->{$name} = $text;
      }
      elsif ($type == $Mail::SpamAssassin::Conf::TYPE_META_TESTS) {
        # Handled by compile_meta_rules()
      }
      elsif ($type == $Mail::SpamAssassin::Conf::TYPE_URI_TESTS) {
        $conf->{uri_tests}->{$priority}->{$name} = $text;
      }
      elsif ($type == $Mail::SpamAssassin::Conf::TYPE_RAWBODY_TESTS) {
        $conf->{rawbody_tests}->{$priority}->{$name} = $text;
      }
      elsif ($type == $Mail::SpamAssassin::Conf::TYPE_FULL_TESTS) {
        $conf->{full_tests}->{$priority}->{$name} = $text;
      }
      elsif ($type == $Mail::SpamAssassin::Conf::TYPE_EMPTY_TESTS) {
      }
      else {
        $self->lint_warn("unknown type $type for $name: $text", $name);
        next;
      }
    }
  }

  $self->lint_trusted_networks();

  if (!$isuserconf) {
    $conf->{main}->call_plugins("finish_parsing_end", { conf => $conf });
  } else {
    $conf->{main}->call_plugins("user_conf_parsing_end", { conf => $conf });
  }

  $conf->found_any_rules();     # before we might delete {tests}

  if (!$conf->{allow_user_rules}) {
    # free up stuff we no longer need
    delete $conf->{tests};
    delete $conf->{priority};
    #test_types are needed - see bug 5503
    #delete $conf->{test_types};
  }
}

# Returns all rulenames matching glob (FOO_*)
sub expand_ruleglob {
  my ($self, $ruleglob, $rulename) = @_;
  my $expanded;
  if (exists $self->{ruleglob_cache}{$ruleglob}) {
    $expanded = $self->{ruleglob_cache}{$ruleglob};
  } else {
    my $reglob = $ruleglob;
    $reglob =~ s/\?/./g;
    $reglob =~ s/\*/.*?/g;
    # Glob rules, but do not match ourselves..
    my @rules = grep {/^${reglob}$/ && $_ ne $rulename} keys %{$self->{conf}->{scores}};
    if (@rules) {
      $expanded = join('+', sort @rules);
    } else {
      $expanded = '0';
    }
  }
  my $logstr = $expanded eq '0' ? 'no matches' : $expanded;
  dbg("rules: meta $rulename rules_matching($ruleglob) expanded: $logstr");
  $self->{ruleglob_cache}{$ruleglob} = $expanded;
  return " ($expanded) ";
}

sub compile_meta_rules {
  my ($self) = @_;
  my (%meta, %meta_deps, %rule_deps);
  my $conf = $self->{conf};

  foreach my $name (keys %{$conf->{tests}}) {
    next unless $conf->{test_types}->{$name} == $Mail::SpamAssassin::Conf::TYPE_META_TESTS;
    my $rule = $conf->{tests}->{$name};

    # Expand meta rules_matching() before lexing
    $rule =~ s/${META_RULES_MATCHING_RE}/$self->expand_ruleglob($1,$name)/ge;

    # Lex the rule into tokens using a rather simple RE method ...
    my @tokens = ($rule =~ /$ARITH_EXPRESSION_LEXER/og);

    # Set the rule blank to start
    $meta{$name} = '';

    # List dependencies that are meta tests in the same priority band
    $meta_deps{$name} = [ ];

    # List all rule dependencies
    $rule_deps{$name} = [ ];

    # Go through each token in the meta rule
    foreach my $token (@tokens) {
      # operator (triage, already validated by is_meta_valid)
      if ($token !~ tr/+&|()!<>=//c) {
        $meta{$name} .= "$token ";
      }
      # rule-like check for local_tests_only
      elsif ($token eq 'local_tests_only') {
        $meta{$name} .= '($_[0]->{main}->{local_tests_only}||0) ';
      }
      # ... rulename?
      elsif ($token =~ IS_RULENAME) {
        # Will end up later in a compiled sub called from do_meta_tests:
        #  $_[0] = $pms
        #  $_[1] = $h ($pms->{tests_already_hit}),
        $meta{$name} .= "(\$_[1]->{'$token'}||0) ";

        if (!exists $conf->{test_types}->{$token}) {
          dbg("rules: meta test $name has undefined dependency '$token'");
          push @{$rule_deps{$name}}, $token;
          next;
        }

        if ($conf->{scores}->{$token} == 0) {
          # bug 5040: net rules in a non-net scoreset
          # there are some cases where this is expected; don't warn
          # in those cases.
          unless ((($conf->get_score_set()) & 1) == 0 &&
              ($conf->{tflags}->{$token}||'') =~ /\bnet\b/)
          {
            dbg("rules: meta test $name has dependency '$token' with a zero score");
          }
        }

        # If the token is another meta rule, add it as a dependency
        if ($conf->{test_types}->{$token} == $Mail::SpamAssassin::Conf::TYPE_META_TESTS) {
          push @{$meta_deps{$name}}, $token;
        }

        # Record all dependencies
        push @{$rule_deps{$name}}, $token;
      }
      # ... number or operator (already validated by is_meta_valid)
      else {
        $meta{$name} .= "$token ";
      }
    }
  }

  # Sort by length of dependencies list.  It's more likely we'll get
  # the dependencies worked out this way.
  my @metas = sort { @{$meta_deps{$a}} <=> @{$meta_deps{$b}} } keys %meta;
  my $count;
  do {
    $count = $#metas;
    my %metas = map { $_ => 1 } @metas; # keep a small cache for fast lookups
    # Go through each meta rule we haven't done yet
    for (my $i = 0 ; $i <= $#metas ; $i++) {
      next if (grep( $metas{$_}, @{ $meta_deps{ $metas[$i] } }));
      splice @metas, $i--, 1;    # remove this rule from our list
    }
  } while ($#metas != $count && $#metas > -1); # run until we can't go anymore

  # If there are any rules left, we can't solve the dependencies so complain
  my %unsolved_metas = map { $_ => 1 } @metas; # keep a small cache for fast lookups
  foreach my $rulename_t (@metas) {
    my $msg = "rules: excluding meta test $rulename_t, unsolved meta dependencies: ".
              join(", ", grep($unsolved_metas{$_}, @{ $meta_deps{$rulename_t} }));
    $self->lint_warn($msg);
  }

  foreach my $name (keys %meta) {
    if ($unsolved_metas{$name}) {
      $conf->{meta_tests}->{$name} = sub { 0 };
      $rule_deps{$name} = [ ];
    }
    if ($meta{$name} eq '( ) ') {
      # Bug 8061:
      # meta FOOBAR () considered a rule declaration to support rule_hits API or
      #  other dynamic rules, only evaluated at finish_meta_rules unless got_hit.
      # Other style metas without dependencies will be evaluated immediately.
      $meta{$name} = '0'; # Evaluating () would result in undef
    }
    elsif (@{$rule_deps{$name}}) {
      $conf->{meta_dependencies}->{$name} = $rule_deps{$name};
      foreach my $deprule (@{$rule_deps{$name}}) {
        $conf->{meta_deprules}->{$deprule}->{$name} = 1;
      }
    } else {
      $conf->{meta_nodeps}->{$name} = 1;
    }
    # Compile meta sub
    eval '$conf->{meta_tests}->{$name} = sub { '.$meta{$name}.'};';
    # Paranoid check
    die "rules: meta compilation failed for $name: '$meta{$name}': $@" if ($@);
  }
}

sub fix_priorities {
  my ($self) = @_;
  my $conf = $self->{conf};

  return unless $conf->{meta_dependencies};    # order requirement

  my $pri = $conf->{priority};
  my $tflags = $conf->{tflags};

  # sort into priority order, lowest first -- this way we ensure that if we
  # rearrange the pri of a rule early on, we cannot accidentally increase its
  # priority later.
  foreach my $rule (sort { $pri->{$a} <=> $pri->{$b} } keys %{$pri}) {
    # we only need to worry about meta rules -- they are the
    # only type of rules which depend on other rules
    my $deps = $conf->{meta_dependencies}->{$rule};
    next unless (defined $deps);

    my $basepri = $pri->{$rule};
    foreach my $dep (@$deps) {
      my $deppri = $pri->{$dep};
      if (defined $deppri && $deppri > $basepri) {
        if ($basepri < -100 && ($tflags->{$dep}||'') =~ /\bnet\b/) {
          dbg("rules: $rule (pri $basepri) requires $dep (pri $deppri): fixed to -100 (net rule)");
          $pri->{$dep} = -100;
          $conf->{priorities}->{-100}++;
        } else {
          dbg("rules: $rule (pri $basepri) requires $dep (pri $deppri): fixed");
          $pri->{$dep} = $basepri;
        }
      }
    }
  }
}

sub fix_tflags {
  my ($self) = @_;
  my $conf = $self->{conf};
  my $tflags = $conf->{tflags};

  # Inherit net tflags from dependencies
  while (my($rulename,$deps) = each %{$conf->{meta_dependencies}}) {
    my $tfl = $tflags->{$rulename}||'';
    next if $tfl =~ /\bnet\b/;
    foreach my $deprule (@$deps) {
      if (($tflags->{$deprule}||'') =~ /\bnet\b/) {
        dbg("rules: meta $rulename inherits tflag net, depends on $deprule");
        $tflags->{$rulename} = $tfl eq '' ? 'net' : "$tfl net";
        last;
      }
    }
  }
}

# Deprecated function
sub pack_eval_method {
  warn "deprecated function pack_eval_method() used\n";
  return ('',undef);
}

sub pack_eval_args {
  my ($self, $args) = @_;

  return [] if $args =~ /^\s+$/;

  # bug 4419: Parse quoted strings, unquoted alphanumerics/floats,
  # unquoted IPv4 and IPv6 addresses, and unquoted common domain names.
  # s// is used so that we can determine whether or not we successfully
  # parsed ALL arguments.
  my @args;
  local($1,$2,$3);
  while ($args =~ s/^\s* (?: (['"]) (.*?) \1 | ( [\d\.:A-Za-z-]+? ) )
                     \s* (?: , \s* | $ )//x) {
    # DO NOT UNTAINT THESE ARGS
    # The eval function that handles these should do that as necessary,
    # we have no idea what acceptable arguments look like here.
    push @args, defined $2 ? $2 : $3;
  }

  if ($args ne '') {
    return undef; ## no critic (ProhibitExplicitReturnUndef)
  }

  return \@args;
}

###########################################################################

sub lint_trusted_networks {
  my ($self) = @_;
  my $conf = $self->{conf};

  # validate trusted_networks and internal_networks, bug 4760.
  # check that all internal_networks are listed in trusted_networks
  # too.  do the same for msa_networks, but check msa_networks against
  # internal_networks if trusted_networks aren't defined

  my ($nt, $matching_against);
  if ($conf->{trusted_networks_configured}) {
    $nt = $conf->{trusted_networks};
    $matching_against = 'trusted_networks';
  } elsif ($conf->{internal_networks_configured}) {
    $nt = $conf->{internal_networks};
    $matching_against = 'internal_networks';
  } else {
    return;
  }

  foreach my $net_type ('internal_networks', 'msa_networks') {
    next unless $conf->{"${net_type}_configured"};
    next if $net_type eq $matching_against;

    my $replace_nets;
    my @valid_net_list;
    my $net_list = $conf->{$net_type};

    foreach my $net (@{$net_list->{nets}}) {
      # don't check to see if an excluded network is included - that's senseless
      if (!$net->{exclude} && !$nt->contains_net($net)) {
        my $msg = "$matching_against doesn't contain $net_type entry '".
                  ($net->{as_string})."'";

        $self->lint_warn($msg, undef);      # complain
        $replace_nets = 1;  # and omit it from the new internal set
      }
      else {
        push @valid_net_list, $net;
      }
    }

    if ($replace_nets) {
      # something was invalid. replace the old nets list with a fixed version
      # (which may be empty)
      $net_list->{nets} = \@valid_net_list;
    }
  }
}

###########################################################################

sub add_test {
  my ($self, $name, $text, $type) = @_;
  my $conf = $self->{conf};

  # Don't allow invalid names ...
  if ($name !~ IS_RULENAME) {
    $self->lint_warn("config: error: rule '$name' has invalid characters ".
	   "(not Alphanumeric + Underscore + starting with a non-digit)\n", $name);
    return;
  }

  # Also set a hard limit for ALL rules (rule names longer than 40
  # characters throw warnings).  Check this separately from the above
  # pattern to avoid vague error messages.
  if (length $name > 100) {
    $self->lint_warn("config: error: rule '$name' is too long ".
	   "(recommended maximum length is 22 characters)\n", $name);
    return;
  }

  # Warn about, but use, long rule names during --lint
  if ($conf->{lint_rules}) {
    if (length($name) > 40 && $name !~ /^__/ && $name !~ /^T_/) {
      $self->lint_warn("config: warning: rule name '$name' is over 40 chars ".
	     "(recommended maximum length is 22 characters)\n", $name);
    }
  }

  # parameter to compile_regexp()
  my $ignore_amre =
    $self->{conf}->{lint_rules} ||
    $self->{conf}->{ignore_always_matching_regexps};

  # all of these rule types are regexps
  if ($type == $Mail::SpamAssassin::Conf::TYPE_BODY_TESTS ||
      $type == $Mail::SpamAssassin::Conf::TYPE_URI_TESTS ||
      $type == $Mail::SpamAssassin::Conf::TYPE_RAWBODY_TESTS ||
      $type == $Mail::SpamAssassin::Conf::TYPE_FULL_TESTS)
  {
    $self->parse_captures($name, \$text);
    my ($rec, $err) = compile_regexp($text, 1, $ignore_amre);
    if (!$rec) {
      $self->lint_warn("config: invalid regexp for $name '$text': $err", $name);
      return;
    }
    $conf->{test_qrs}->{$name} = $rec;
  }
  elsif ($type == $Mail::SpamAssassin::Conf::TYPE_HEAD_TESTS)
  {
    # If redefining header test, clear out opt hashes so they don't leak to
    # the new test.  There are separate hashes for options as it saves lots
    # of memory (exists, neg, if-unset are rarely used).
    if (exists $conf->{tests}->{$name}) {
      delete $conf->{test_opt_exists}->{$name};
      delete $conf->{test_opt_unset}->{$name};
      delete $conf->{test_opt_neg}->{$name};
    }
    local($1,$2,$3);
    # RFC 5322 section 3.6.8, ftext printable US-ASCII chars not including ":"
    # no re "strict";  # since perl 5.21.8: Ranges of ASCII printables...
    if ($text =~ /^exists:(.*)/) {
      my $hdr = $1;
      # $hdr used in eval text, validate carefully
      if ($hdr !~ /^[\w.-]+:?$/) {
        $self->lint_warn("config: invalid head test $name header: $hdr");
        return;
      }
      $hdr =~ s/:$//;
      $conf->{test_opt_header}->{$name} = $hdr;
      $conf->{test_opt_exists}->{$name} = 1;
    } else {
      # $hdr used in eval text, validate carefully
      # check :addr etc header options
      if ($text !~ /^([\w.-]+(?:\:|(?:\:[a-z]+){1,2})?)\s*([=!]~)\s*(.+)$/) {
        $self->lint_warn("config: invalid head test $name: $text");
        return;
      }
      my ($hdr, $op, $pat) = ($1, $2, $3);
      $hdr =~ s/:$//;
      if ($hdr =~ /:(?!(?:raw|addr|name|host|domain|ip|revip|first|last)\b)/i) {
        $self->lint_warn("config: invalid header modifier for $name: $hdr", $name);
        return;
      }
      if ($pat =~ s/\s+\[if-unset:\s+(.+)\]$//) {
        $conf->{test_opt_unset}->{$name} = $1;
      }
      $self->parse_captures($name, \$pat);
      my ($rec, $err) = compile_regexp($pat, 1, $ignore_amre);
      if (!$rec) {
        $self->lint_warn("config: invalid regexp for $name '$pat': $err", $name);
        return;
      }
      $conf->{test_qrs}->{$name} = $rec;
      $conf->{test_opt_header}->{$name} = $hdr;
      $conf->{test_opt_neg}->{$name} = 1 if $op eq '!~';
    }
  }
  elsif ($type == $Mail::SpamAssassin::Conf::TYPE_META_TESTS)
  {
    if ($self->is_meta_valid($name, $text)) {
      # Untaint now once and not repeatedly later
      $text = untaint_var($text);
    } else {
      return;
    }
  }
  elsif (($type & 1) == 1) { # *_EVALS
    # create eval_to_rule mappings
    if (my ($function) = ($text =~ m/(.*?)\s*\(.*?\)\s*$/)) {
      push @{$conf->{eval_to_rule}->{$function}}, $name;
    }
  }

  $conf->{tests}->{$name} = $text;
  $conf->{test_types}->{$name} = $type;

  if ($name =~ /^AUTOLEARNTEST/) {
     dbg("config: auto-learn: $name has type $type = $conf->{test_types}->{$name} during add_test\n");
  }

  $conf->{priority}->{$name} ||= 0;

  if ($conf->{main}->{keep_config_parsing_metadata}) {
    # {source_file} eats lots of memory and is unused unless
    # keep_config_parsing_metadata is set (ruleqa stuff)
    $conf->{source_file}->{$name} = $self->{currentfile};

    $conf->{if_stack}->{$name} = $self->get_if_stack_as_string();

    if ($self->{file_scoped_attrs}->{testrules}) {
      $conf->{testrules}->{$name} = 1;   # used in build/mkupdates/listpromotable
    }
  }

  # if we found this rule in a user_prefs file, it's a user rule -- note that
  # we may need to recompile the rule code for this type (if they've already
  # been compiled, e.g. in spamd).
  #
  # Note: the want_rebuild_for_type 'flag' is actually a counter; it is decremented
  # after each scan.  This ensures that we always recompile at least once more;
  # once to *define* the rule, and once afterwards to *undefine* the rule in the
  # compiled ruleset again.
  #
  # If two consecutive scans use user rules, that's ok -- the second one will
  # reset the counter, and we'll still recompile just once afterwards to undefine
  # the rule again.
  #
  if ($self->{scoresonly}) {
    $conf->{want_rebuild_for_type}->{$type} = 2;
    $conf->{user_defined_rules}->{$name} = 1;
  }
}

sub add_regression_test {
  my ($self, $name, $ok_or_fail, $string) = @_;
  my $conf = $self->{conf};

  if ($conf->{regression_tests}->{$name}) {
    push @{$conf->{regression_tests}->{$name}}, [$ok_or_fail, $string];
  }
  else {
    # initialize the array, and create one element
    $conf->{regression_tests}->{$name} = [ [$ok_or_fail, $string] ];
  }
}

sub is_meta_valid {
  my ($self, $name, $rule) = @_;

  # $meta is a degenerate translation of the rule, replacing all variables (i.e. rule names) with 0. 
  my $meta = '';

  # Paranoid check (Bug #7557)
  if ($rule =~ /(?:\:\:|->|[\$\@\%\;\{\}])/) {
    warn("config: invalid meta $name rule: $rule\n");
    return 0;
  }

  # Process expandable functions before lexing
  $rule =~ s/${META_RULES_MATCHING_RE}/ 0 /g;

  # Lex the rule into tokens using a rather simple RE method ...
  my @tokens = ($rule =~ /($ARITH_EXPRESSION_LEXER)/og);
  if (length($name) == 1) {
    for (@tokens) {
      print "$name $_\n "  or die "Error writing token: $!";
    }
  }

  # Go through each token in the meta rule
  foreach my $token (@tokens) {
    # If the token is a syntactically legal rule name, make it zero
    if ($token =~ IS_RULENAME) {
      $meta .= "0 ";
    }
    # if it is a (decimal) number or a string of 1 or 2 punctuation
    # characters (i.e. operators) tack it onto the degenerate rule
    elsif ($token =~ /^(\d+(?:\.\d+)?|[[:punct:]]{1,2})\z/s) {
      $meta .= "$token ";
    }
    # Skip anything unknown (Bug #7557)
    else {
      $self->lint_warn("config: invalid meta $name token: $token", $name);
      return 0;
    }
  }

  $meta = untaint_var($meta); # was carefully checked
  my $evalstr = 'my $x = '.$meta.'; 1;';
  if (eval $evalstr) {
    return 1;
  }
  my $err = $@ ne '' ? $@ : "errno=$!";  chomp $err;
  $err =~ s/\s+(?:at|near)\b.*//s;
  $err =~ s/Illegal division by zero/division by zero possible/i;
  $self->lint_warn("config: invalid expression for rule $name: \"$rule\": $err\n", $name);
  return 0;
}

sub parse_captures {
  my ($self, $name, $re) = @_;

  # Check for named regex capture templates
  if (index($$re, '%{') >= 0) {
    local($1);
    # Replace %{FOO} with %\{FOO\} so compile_regexp doesn't fail with unescaped left brace
    while ($$re =~ s/(?<!\\)\%\{([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*(?:\([^\)\}]*\))?)\}/%\\{$1\\}/g) {
      dbg("config: found named capture for rule $name: $1");
      $self->{conf}->{capture_template_rules}->{$name}->{$1} = 1;
    }
  }
  # Make rules with captures run before anything else
  if ($$re =~ /\(\?P?[<'][A-Z]/) {
    dbg("config: adjusting regex capture rule $name priority to -10000");
    $self->{conf}->{priority}->{$name} = -10000;
    $self->{conf}->{capture_rules}->{$name} = 1;
  }
}

# Deprecated functions, leave just in case..
sub is_delimited_regexp_valid {
  my ($self, $rule, $re) = @_;
  warn "deprecated is_delimited_regexp_valid() called, use compile_regexp()\n";
  my ($rec, $err) = compile_regexp($re, 1, 1);
  return $rec;
}
sub is_regexp_valid {
  my ($self, $rule, $re) = @_;
  warn "deprecated is_regexp_valid() called, use compile_regexp()\n";
  my ($rec, $err) = compile_regexp($re, 1, 1);
  return $rec;
}
sub is_always_matching_regexp {
  warn "deprecated is_always_matching_regexp() called\n";
  return;
}

###########################################################################

sub add_to_addrlist {
  my ($self, $singlelist, @addrs) = @_;
  my $conf = $self->{conf};

  foreach my $addr (@addrs) {
    $addr = lc $addr;
    my $re = $addr;
    $re =~ s/[\000\\\(]/_/gs;			# paranoia
    $re =~ s/([^\*\?_a-zA-Z0-9])/\\$1/g;	# escape any possible metachars
    $re =~ tr/?/./;				# "?" -> "."
    $re =~ s/\*+/\.\*/g;			# "*" -> "any string"
    my ($rec, $err) = compile_regexp("^${re}\$", 0);
    if (!$rec) {
      warn "could not compile $singlelist '$addr': $err";
      return;
    }
    $conf->{$singlelist}->{$addr} = $rec;
  }
}

sub add_to_addrlist_rcvd {
  my ($self, $listname, $addr, $domain) = @_;
  my $conf = $self->{conf};

  $domain = lc $domain;
  $addr = lc $addr;
  if ($conf->{$listname}->{$addr}) {
    push @{$conf->{$listname}->{$addr}{domain}}, $domain;
  }
  else {
    my $re = $addr;
    $re =~ s/[\000\\\(]/_/gs;			# paranoia
    $re =~ s/([^\*\?_a-zA-Z0-9])/\\$1/g;	# escape any possible metachars
    $re =~ tr/?/./;				# "?" -> "."
    $re =~ s/\*+/\.\*/g;			# "*" -> "any string"
    my ($rec, $err) = compile_regexp("^${re}\$", 0);
    if (!$rec) {
      warn "could not compile $listname '$addr': $err";
      return;
    }
    $conf->{$listname}->{$addr}{re} = $rec;
    $conf->{$listname}->{$addr}{domain} = [ $domain ];
  }
}

sub remove_from_addrlist {
  my ($self, $singlelist, @addrs) = @_;
  my $conf = $self->{conf};

  foreach my $addr (@addrs) {
    delete($conf->{$singlelist}->{lc $addr});
  }
}

sub remove_from_addrlist_rcvd {
  my ($self, $listname, @addrs) = @_;
  my $conf = $self->{conf};

  foreach my $addr (@addrs) {
    delete($conf->{$listname}->{lc $addr});
  }
}

sub add_to_addrlist_dkim {
  add_to_addrlist_rcvd(@_);
}

sub remove_from_addrlist_dkim {
  my ($self, $listname, $addr, $domain) = @_;
  my $conf = $self->{conf};
  my $conf_lname = $conf->{$listname};

  $addr = lc $addr;
  if ($conf_lname->{$addr}) {
    $domain = lc $domain;
    my $domains_listref = $conf_lname->{$addr}{domain};
    # removing $domain from the list
    my @replacement = grep { lc $_ ne $domain } @$domains_listref;
    if (!@replacement) {  # nothing left, remove the entire addr entry
      delete($conf_lname->{$addr});
    } elsif (@replacement != @$domains_listref) {  # anything changed?
      $conf_lname->{$addr}{domain} = \@replacement;
    }
  }
}


###########################################################################

sub fix_path_relative_to_current_file {
  my ($self, $path) = @_;

  # the path may be specified as "~/foo", so deal with that
  $path = $self->{conf}->{main}->sed_path($path);

  if (!File::Spec->file_name_is_absolute ($path)) {
    my ($vol, $dirs, $file) = File::Spec->splitpath ($self->{currentfile});
    $path = File::Spec->catpath ($vol, $dirs, $path);
    dbg("config: fixed relative path: $path");
  }
  return $path;
}

###########################################################################

sub lint_warn {
  my ($self, $msg, $rule, $iserror) = @_;

  if (!defined $iserror) { $iserror = 1; }

  if ($self->{conf}->{main}->{lint_callback}) {
    $self->{conf}->{main}->{lint_callback}->(
          msg => $msg,
          rule => $rule,
          iserror => $iserror
        );
  }
  elsif ($self->{conf}->{lint_rules}) {
    warn $msg."\n";
  }
  else {
    info($msg);
  }

  if ($iserror) {
    $self->{conf}->{errors}++;
  }
}

###########################################################################

sub get_if_stack_as_string {
  my ($self) = @_;
  return join ' ', map {
    $_->{conditional}
  } @{$self->{if_stack}};
}

###########################################################################

1;
