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
# # Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# </@LICENSE>
#
###########################################################################

package Mail::SpamAssassin::Plugin::PhishTag;

use strict;
use warnings;
use re 'taint';
use Errno qw(EBADF);

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;

our @ISA = qw(Mail::SpamAssassin::Plugin);

sub new{
  my ($class, $mailsa)=@_;
  $class=ref($class) ||$class;
  my $self = $class->SUPER::new($mailsa);
  bless($self,$class);
  $self->set_config($mailsa->{conf});
  return $self;
}

sub set_config{
  my($self, $conf) = @_;
  my @cmds;

  push (@cmds, {
    setting => 'trigger_target',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
    is_admin => 1,
  });

  push (@cmds, {
    setting => 'trigger_config',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    is_admin => 1,
    default => '',
  });

  push (@cmds, {
    setting => 'trigger_ratio',
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
    is_admin => 1,
    default =>  0,
  });

  $conf->{parser}->register_commands(\@cmds);
}

#prepare the plugin
sub check_start{
  my ($self, $params) = @_;
  my $pms = $params->{permsgstatus};
  
  #initialize the PHISHTAG data structure for 
  #saving configuration information
  $pms->{PHISHTAG} = {};
  $pms->{PHISHTAG}->{triggers}={};
  $pms->{PHISHTAG}->{targets}=[];

  #read the configuration info
  $self->read_configfile($params);
  $self->read_settings($params);
}

sub read_settings{
  my ($self, $params) = @_;
  my $pms = $params->{permsgstatus};

  my $triggers= $pms->{PHISHTAG}->{triggers};
  my $targets= $pms->{PHISHTAG}->{targets};
  while (my ($tname,$ttarget)=each %{$pms->{conf}->{trigger_target}}){
      push @$targets, [$ttarget, $tname];
      $$triggers{$tname}=0;
  }
}


sub read_configfile{
  my ($self, $params) = @_;
  my $pms = $params->{permsgstatus};

  #nothing interesting here if there is not a configuration file
  return if($pms->{conf}->{trigger_config} !~/\S/);

  my $triggers= $pms->{PHISHTAG}->{triggers};
  my $targets= $pms->{PHISHTAG}->{targets};

  my $target;
  local *F;
  open(F, '<', $pms->{conf}->{trigger_config});
  for ($!=0; <F>; $!=0) {
      #each entry is separated by blank lines
      undef($target) if(!/\S/);

      #lines that start with pound are comments
      next if(/^\s*\#/);

      #an entry starts with a URL line prefixed with the word "target"
      if(/^target\s+(\S+)/){
	  $target=[$1];
	  push @$targets,$target;
      }
      #add the test to the list of listened triggers
      #and          to the triggers of the last target
      elsif(defined $target){
	  s/\s+//g;
	  $$triggers{$_}=0;
	  push @$target, $_;
      }
  }
  defined $_ || $!==0  or
    $!==EBADF ? dbg("PHISHTAG: error reading config file: $!")
              : die "error reading config file: $!";
  close(F)  or die "error closing config file: $!";
}

sub hit_rule {
  my ($self, $params) = @_;
  my $pms = $params->{permsgstatus};
  my $rulename = $params->{rulename};
 
  #mark the rule as hit
  if(defined($pms->{PHISHTAG}->{triggers}->{$rulename})){
      $pms->{PHISHTAG}->{triggers}->{$rulename}=1;
      dbg("PHISHTAG: $rulename has been caught\n");
  }
}

sub check_post_learn {
  my ($self, $params) = @_;
  my $pms = $params->{permsgstatus};

  #find out which targets have fulfilled their requirements
  my $triggers= $pms->{PHISHTAG}->{triggers};
  my $targets= $pms->{PHISHTAG}->{targets};
  my @filled;
  foreach my $target(@$targets){
      my $uri= $$target[0];
      my $fulfilled=1;
      #all the triggers of a target have to exist for it to be fulfilled
      foreach my $i(1..$#$target){
	  if(! $triggers->{$$target[$i]}){
	      $fulfilled=0;
	      last;
	  }
      }
      if($fulfilled){
	  push @filled, $uri;
	  dbg("PHISHTAG: Fulfilled $uri\n");
      }
  }
  
  if(scalar(@filled) &&
     $pms->{conf}->{trigger_ratio} > rand(100)){
      $pms->{PHISHTAG}->{letgo}=0;
      $pms->{PHISHTAG}->{uri}=$filled[int(rand(scalar(@filled)))];
      
      dbg("PHISHTAG: Decided to keep this email and point to ". 
	  $pms->{PHISHTAG}->{uri});
      #make sure that SpamAssassin does not remove this email
      $pms->got_hit("PHISHTAG_TOSS", 
		    "BODY: ", 
		    score => -100);
  }
  else{
      dbg("PHISHTAG: Will let this email to SpamAssassin's discretion\n");
      $pms->{PHISHTAG}->{letgo}=1;
  }
  

  #nothing interesting here, if we will not rewrite the email
  if($pms->{PHISHTAG}->{letgo}){
      return;
  }
  
  my $pristine_body=\$pms->{msg}->{pristine_body};
  #dbg("PRISTINE>>\n".$$pristine_body);

  my $uris = $pms->get_uri_detail_list();
  #rewrite the url
  while (my($uri, $info) = each %{$uris}) { 
      if(defined ($info->{types}->{a})){
	  $$pristine_body=~s/$uri/$pms->{PHISHTAG}->{uri}/mg;
      }
  }
  dbg("PRISTINE>>\n".$$pristine_body);
}

1;
__END__

=head1 NAME

PhishTag - SpamAssassin plugin for redirecting links in incoming emails.

=head1 SYNOPSIS

 loadplugin     Mail::SpamAssassin::Plugin::PhishTag

 trigger_ratio    0.1
 trigger_target   RULE_NAME  http://www.antiphishing.org/consumer_recs.html

=head1 DESCRIPTION

PhishTag enables administrators to rewrite links in emails that trigger certain
tests, preferably anti-phishing blocklist tests. The plugin will inhibit the
blocking of a portion of the emails that trigger the test by SpamAssassin, and
let them pass to the users' inbox after the rewrite. It is useful in providing
training to email users about company policies and general email usage.

=head1 OPTIONS

The following options can be set by modifying the configuration file.

=over 4

=item * trigger_ratio percentage_value

Sets the probability in percentage that a positive test will trigger the 
email rewrite, e.g. 0.1 will rewrite on the average 1 in 1000 emails that 
match the trigger.

=item * trigger_target RULE_NAME http_url

The name of the test which would trigger the email rewrite; all the URLs 
will be replaced by http_url.

=back

=head1 DOWNLOAD

The source of this plugin is available at: 
http://umut.topkara.org/PhishTag/PhishTag.pm
a sample configuration file is also available:
http://umut.topkara.org/PhishTag/PhishTag.cf

=head1 SEE ALSO

Check the list of tests performed by SpamAssassin to modify the
configuration file to match your needs from 
https://spamassassin.apache.org/tests.html

=head1 AUTHOR

Umut Topkara, 2008, E<lt>umut@topkara.orgE<gt>
http://umut.topkara.org

=head1 COPYRIGHT AND LICENSE

This plugin is free software; you can redistribute it and/or modify
it under the same terms as SpamAssassin itself, either version 3.2.4 
or, at your option, any later version of SpamAssassin you may have 
available.


=cut
