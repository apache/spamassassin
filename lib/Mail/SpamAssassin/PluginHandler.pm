# <@LICENSE>
# ====================================================================
# The Apache Software License, Version 1.1
# 
# Copyright (c) 2000 The Apache Software Foundation.  All rights
# reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
# 
# 3. The end-user documentation included with the redistribution,
#    if any, must include the following acknowledgment:
#       "This product includes software developed by the
#        Apache Software Foundation (http://www.apache.org/)."
#    Alternately, this acknowledgment may appear in the software itself,
#    if and wherever such third-party acknowledgments normally appear.
# 
# 4. The names "Apache" and "Apache Software Foundation" must
#    not be used to endorse or promote products derived from this
#    software without prior written permission. For written
#    permission, please contact apache@apache.org.
# 
# 5. Products derived from this software may not be called "Apache",
#    nor may "Apache" appear in their name, without prior written
#    permission of the Apache Software Foundation.
# 
# THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESSED OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED.  IN NO EVENT SHALL THE APACHE SOFTWARE FOUNDATION OR
# ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
# USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
# OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
# ====================================================================
# 
# This software consists of voluntary contributions made by many
# individuals on behalf of the Apache Software Foundation.  For more
# information on the Apache Software Foundation, please see
# <http://www.apache.org/>.
# 
# Portions of this software are based upon public domain software
# originally written at the National Center for Supercomputing Applications,
# University of Illinois, Urbana-Champaign.
# </@LICENSE>

=head1 NAME

Mail::SpamAssassin::PluginHandler - SpamAssassin plugin handler

=cut

package Mail::SpamAssassin::PluginHandler;
use Mail::SpamAssassin;
use Mail::SpamAssassin::Plugin;

use strict;
use bytes;

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

  dbg ("plugin: loading $path");

  if (!do $path) {
    if ($@) { warn "failed to parse plugin $path: $@\n"; }
    elsif ($!) { warn "failed to load plugin $path: $!\n"; }
  }

  my $plugin = eval $package.q{->new ($self->{main}); };

  if ($@ || !$plugin) { warn "failed to create plugin $package: $@\n"; }

  if ($plugin) {
    $self->{main}->{plugins}->register_plugin ($plugin);
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
  my $ret;

  foreach my $plugin (@{$self->{plugins}}) {
    $plugin->{_inhibit_further_callbacks} = 0;

    dbg ("plugin: calling $subname on $plugin");
    my $methodref = $plugin->can ($subname);
    $ret = &$methodref ($plugin, @_);

    if ($plugin->{_inhibit_further_callbacks}) {
      dbg ("plugin: $plugin inhibited further callbacks");
      last;
    }
  }

  return $ret;
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
