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

Mail::SpamAssassin::PluginHandler - SpamAssassin plugin handler

=cut

package Mail::SpamAssassin::PluginHandler;

use Mail::SpamAssassin;
use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Util;
use Mail::SpamAssassin::Logger;

use strict;
use warnings;
use bytes;
use re 'taint';
use File::Spec;

use vars qw{
  @ISA @CONFIG_TIME_HOOKS
};

@ISA = qw();

#Removed $VERSION per BUG 6422
#$VERSION = 'bogus';     # avoid CPAN.pm picking up version strings later

# Normally, the list of active plugins that should be called for a given hook
# method name is compiled and cached at runtime.  This means that later calls
# will not have to traverse the entire plugin list more than once, since the
# list of plugins that implement that hook is already cached.
#
# However, some hooks should not receive this treatment. One of these is
# parse_config, which may be compiled before all config files have been read;
# if a plugin is loaded from a config file after this has been compiled, it
# will not get callbacks.
#
# Any other such hooks that may be compiled at config-parse-time should be
# listed here.

@CONFIG_TIME_HOOKS = qw( parse_config );

###########################################################################

sub new {
  my $class = shift;
  my $main = shift;
  $class = ref($class) || $class;
  my $self = {
    plugins		=> [ ],
    cbs 		=> { },
    main		=> $main
  };
  bless ($self, $class);
  $self;
}

###########################################################################

sub load_plugin {
  my ($self, $package, $path, $silent) = @_;

  # Don't load the same plugin twice!
  # Do this *before* calling ->new(), otherwise eval rules will be
  # registered on a nonexistent object
  foreach my $old_plugin (@{$self->{plugins}}) {
    if (ref($old_plugin) eq $package) {
      dbg("plugin: did not register $package, already registered");
      return;
    }
  }

  my $ret;
  if ($path) {
    # bug 3717:
    # At least Perl 5.8.0 seems to confuse $cwd internally at some point -- we
    # need to use an absolute path here else we get a "File not found" error.
    $path = Mail::SpamAssassin::Util::untaint_file_path(
              File::Spec->rel2abs($path)
	    );

    # if (exists $INC{$path}) {
      # dbg("plugin: not loading $package from $path, already loaded");
      # return;
    # }

    dbg("plugin: loading $package from $path");

    # use require instead of "do", so we get built-in $INC{filename}
    # smarts
    $ret = eval { require $path; };
  }
  else {
    dbg("plugin: loading $package from \@INC");
    $ret = eval qq{ require $package; };
    $path = "(from \@INC)";
  }

  if (!$ret) {
    if ($silent) {
      if ($@) { dbg("plugin: failed to parse tryplugin $path: $@\n"); }
      elsif ($!) { dbg("plugin: failed to load tryplugin $path: $!\n"); }
    }
    else {
      if ($@) { warn "plugin: failed to parse plugin $path: $@\n"; }
      elsif ($!) { warn "plugin: failed to load plugin $path: $!\n"; }
    }
    return;           # failure!  no point in continuing here
  }

  my $plugin = eval $package.q{->new ($self->{main}); };

  if ($@ || !$plugin) {
    warn "plugin: failed to create instance of plugin $package: $@\n";
  }

  if ($plugin) {
    $self->{main}->{plugins}->register_plugin ($plugin);
    $self->{main}->{conf}->load_plugin_succeeded ($plugin, $package, $path);
  }
}

sub register_plugin {
  my ($self, $plugin) = @_;
  $plugin->{main} = $self->{main};
  push (@{$self->{plugins}}, $plugin);
  # dbg("plugin: registered $plugin");

  # invalidate cache entries for any configuration-time hooks, in case
  # one has already been built; this plugin may implement that hook!
  foreach my $subname (@CONFIG_TIME_HOOKS) {
    delete $self->{cbs}->{$subname};
  }
}

###########################################################################

sub have_callback {
  my ($self, $subname) = @_;

  # have we set up the cache entry for this callback type?
  if (!exists $self->{cbs}->{$subname}) {
    # nope.  run through all registered plugins and see which ones
    # implement this type of callback.  sort by priority

    my %subsbypri;
    foreach my $plugin (@{$self->{plugins}}) {
      my $methodref = $plugin->can ($subname);
      if (defined $methodref) {
        my $pri = $plugin->{method_priority}->{$subname} || 0;

        $subsbypri{$pri} ||= [];
        push (@{$subsbypri{$pri}}, [ $plugin, $methodref ]);

        dbg("plugin: ${plugin} implements '$subname', priority $pri");
      }
    }

    my @subs;
    foreach my $pri (sort { $a <=> $b } keys %subsbypri) {
      push @subs, @{$subsbypri{$pri}};
    }

    $self->{cbs}->{$subname} = \@subs;
  }

  return scalar(@{$self->{cbs}->{$subname}});
}

sub callback {
  my $self = shift;
  my $subname = shift;
  my ($ret, $overallret);

  # have we set up the cache entry for this callback type?
  if (!exists $self->{cbs}->{$subname}) {
    return unless $self->have_callback($subname);
  }

  foreach my $cbpair (@{$self->{cbs}->{$subname}}) {
    my ($plugin, $methodref) = @$cbpair;

    $plugin->{_inhibit_further_callbacks} = 0;

    eval {
      $ret = &$methodref ($plugin, @_);
      1;
    } or do {
      my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
      warn "plugin: eval failed: $eval_stat\n";
    };

    if (defined $ret) {
      # dbg("plugin: ${plugin}->${methodref} => $ret");
      # we are interested in defined but false results too
      $overallret = $ret  if $ret || !defined $overallret;
    }

    if ($plugin->{_inhibit_further_callbacks}) {
      # dbg("plugin: $plugin inhibited further callbacks");
      last;
    }
  }

  return $overallret;
}

###########################################################################

sub get_loaded_plugins_list {
  my ($self) = @_;
  return @{$self->{plugins}};
}

###########################################################################

sub finish {
  my $self = shift;
  delete $self->{cbs};
  foreach my $plugin (@{$self->{plugins}}) {
    $plugin->finish();
    delete $plugin->{main};
  }
  delete $self->{plugins};
  delete $self->{main};
}

###########################################################################

1;
