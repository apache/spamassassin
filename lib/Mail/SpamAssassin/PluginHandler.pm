# <@LICENSE>
# Copyright 2004 Apache Software Foundation
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
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

use strict;
use bytes;
use File::Spec;

use vars qw{
  @ISA $VERSION
};

@ISA = qw();

$VERSION = 'bogus';     # avoid CPAN.pm picking up version strings later

###########################################################################

sub new {
  my $class = shift;
  my $main = shift;
  $class = ref($class) || $class;
  my $self = {
    plugins		=> [ ],
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
    dbg ("plugin: loading $package from $path");

    if (!File::Spec->file_name_is_absolute ($path)) {
      my ($vol, $dirs, $file) = File::Spec->splitpath ($self->{currentfile});
      $path = File::Spec->catpath ($vol, $dirs, $path);
      dbg ("plugin: fixed relative path: $path");
    }
    $ret = do $path;
  }
  else {
    dbg ("plugin: loading $package from \@INC");
    $ret = eval qq{ require $package; };
    $path = "(from \@INC)";
  }

  if (!$ret) {
    if ($@) { warn "failed to parse plugin $path: $@\n"; }
    elsif ($!) { warn "failed to load plugin $path: $!\n"; }
  }

  my $plugin = eval $package.q{->new ($self->{main}); };

  if ($@ || !$plugin) { warn "failed to create instance of plugin $package: $@\n"; }

  # Don't load the same plugin twice!
  foreach my $old_plugin (@{$self->{plugins}}) {
    if (ref($old_plugin) eq ref($plugin)) {
      warn "Plugin " . ref($old_plugin) . " already registered\n";
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
  dbg ("plugin: registered $plugin");
}

###########################################################################

sub callback {
  my $self = shift;
  my $subname = shift;
  my ($ret, $overallret);

  foreach my $plugin (@{$self->{plugins}}) {
    $plugin->{_inhibit_further_callbacks} = 0;

    my $methodref = $plugin->can ($subname);

    if (defined $methodref) {
      eval {
	$ret = &$methodref ($plugin, @_);
      };
      if ($ret) {
        dbg ("plugin: ${plugin}->${subname} => $ret");
        $overallret = $ret;

        if ($ret == $Mail::SpamAssassin::Plugin::INHIBIT_CALLBACKS) {
          $plugin->{_inhibit_further_callbacks} = 1;
          $ret = 1;
        }
      }
    }

    if ($plugin->{_inhibit_further_callbacks}) {
      dbg ("plugin: $plugin inhibited further callbacks");
      last;
    }
  }

  $overallret ||= $ret;
  return $overallret;
}

###########################################################################

sub finish {
  my $self = shift;
  foreach my $plugin (@{$self->{plugins}}) {
    $plugin->finish();
    delete $plugin->{main};
  }
  delete $self->{plugins};
  delete $self->{main};
}

###########################################################################

sub dbg { Mail::SpamAssassin::dbg (@_); }

1;
