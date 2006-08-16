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
use File::Spec;

use vars qw{
  @ISA $VERSION @CONFIG_TIME_HOOKS
};

@ISA = qw();

$VERSION = 'bogus';     # avoid CPAN.pm picking up version strings later

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
  my ($self, $package, $path) = @_;

  my $ret;
  if ($path) {
    # bug 3717:
    # At least Perl 5.8.0 seems to confuse $cwd internally at some point -- we
    # need to use an absolute path here else we get a "File not found" error.
    $path = Mail::SpamAssassin::Util::untaint_file_path(
              File::Spec->rel2abs($path)
	    );
    dbg("plugin: loading $package from $path");
    $ret = do $path;
  }
  else {
    dbg("plugin: loading $package from \@INC");
    $ret = eval qq{ require $package; };
    $path = "(from \@INC)";
  }

  if (!$ret) {
    if ($@) { warn "plugin: failed to parse plugin $path: $@\n"; }
    elsif ($!) { warn "plugin: failed to load plugin $path: $!\n"; }
  }

  my $plugin = eval $package.q{->new ($self->{main}); };

  if ($@ || !$plugin) { warn "plugin: failed to create instance of plugin $package: $@\n"; }

  # Don't load the same plugin twice!
  foreach my $old_plugin (@{$self->{plugins}}) {
    if (ref($old_plugin) eq ref($plugin)) {
      dbg("plugin: did not register $plugin, already registered");
      return;
    }
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
  dbg("plugin: registered $plugin");

  # invalidate cache entries for any configuration-time hooks, in case
  # one has already been built; this plugin may implement that hook!
  foreach my $subname (@CONFIG_TIME_HOOKS) {
    delete $self->{cbs}->{$subname};
  }
}

###########################################################################

sub callback {
  my $self = shift;
  my $subname = shift;
  my ($ret, $overallret);

  # have we set up the cache entry for this callback type?
  if (!exists $self->{cbs}->{$subname}) {
    # nope.  run through all registered plugins and see which ones
    # implement this type of callback
    my @subs = ();
    foreach my $plugin (@{$self->{plugins}}) {
      my $methodref = $plugin->can ($subname);
      if (defined $methodref) {
        push (@subs, [ $plugin, $methodref ]);
        dbg("plugin: ${plugin} implements '$subname'");
      }
    }
    $self->{cbs}->{$subname} = \@subs;
  }

  foreach my $cbpair (@{$self->{cbs}->{$subname}}) {
    my ($plugin, $methodref) = @$cbpair;

    $plugin->{_inhibit_further_callbacks} = 0;

    eval {
      $ret = &$methodref ($plugin, @_);
    };
    if ($@) {
      warn "plugin: eval failed: $@";
    }

    if ($ret) {
      #dbg("plugin: ${plugin}->${methodref} => $ret");
      $overallret = $ret;
    }

    if ($plugin->{_inhibit_further_callbacks}) {
      # dbg("plugin: $plugin inhibited further callbacks");
      last;
    }
  }

  $overallret ||= $ret;
  return $overallret;
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
