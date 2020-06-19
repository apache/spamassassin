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

AntiVirus - simple anti-virus tests

=head1 SYNOPSIS

  loadplugin     Mail::SpamAssassin::Plugin::AntiVirus

  body MICROSOFT_EXECUTABLE eval:check_microsoft_executable()
  body MIME_SUSPECT_NAME    eval:check_suspect_name()

=head1 DESCRIPTION

The MICROSOFT_EXECUTABLE rule works by checking for 3 possibilities in
the message in any application/* or text/* part in the message:

=over 4

=item - in text parts, look for a uuencoded executable start string

=item - in application parts, look for filenames ending in an executable extension

=item - in application parts, look for a base64 encoded executable start string

=back

=cut

package Mail::SpamAssassin::Plugin::AntiVirus;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Util;
use strict;
use warnings;
# use bytes;
use re 'taint';

our @ISA = qw(Mail::SpamAssassin::Plugin);

# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->register_eval_rule("check_microsoft_executable", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule("check_suspect_name", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);

  return $self;
}

sub check_microsoft_executable {
  my ($self, $pms) = @_;

  _check_attachments(@_) unless exists $pms->{antivirus_microsoft_exe};

  return $pms->{antivirus_microsoft_exe};
}

sub check_suspect_name {
  my ($self, $pms) = @_;

  _check_attachments(@_) unless exists $pms->{antivirus_suspect_name};

  return $pms->{antivirus_suspect_name};
}

sub _check_attachments {
  my ($self, $pms) = @_;

  $pms->{antivirus_microsoft_exe} = 0;
  $pms->{antivirus_suspect_name} = 0;

  # MICROSOFT_EXECUTABLE triggered here
  foreach my $p ($pms->{msg}->find_parts(qr/./, 1)) {
    my ($ctype, $boundary, $charset, $name) =
      Mail::SpamAssassin::Util::parse_content_type($p->get_header('content-type'));

    $name = lc($name || '');

    my $cte = lc($p->get_header('content-transfer-encoding') || '');
    $ctype = lc $ctype;

    if ($name && $name =~ /\.(?:ade|adp|asx|bas|bat|chm|cmd|com|cpl|crt|dll|exe|hlp|hta|inf|ins|isp|js|jse|lnk|mda|mdb|mde|mdt|mdw|mdz|msc|msi|msp|mst|nws|ops|pcd|pif|prf|reg|scf|scr\??|sct|shb|shs|shm|swf|url|vb|vbe|vbs|vbx|vxd|wsc|wsf|wsh)$/)
    {
      # file extension indicates an executable
      $pms->{antivirus_microsoft_exe} = 1;
    }
    elsif (index($cte, 'base64') >= 0 && defined $p->raw()->[0] &&
	   $p->raw()->[0] =~ /^TV[opqr].A..[AB].[AQgw][A-H].A/)
    {
      # base64-encoded executable
      $pms->{antivirus_microsoft_exe} = 1;
    }
    elsif ($ctype =~ /^text\b/) {
      # uuencoded executable
      for (@{$p->raw()}) {
	if (/^M35[GHIJK].`..`..*````/) {
	  # uuencoded executable
	  $pms->{antivirus_microsoft_exe} = 1;
	}
      }
    }

    # MIME_SUSPECT_NAME triggered here
    if ($name && $ctype ne "application/octet-stream") {
      $name =~ s/.*\.//;
      $ctype =~ s@/(x-|vnd\.)@/@;

      if (
	  # text
	  (($name =~ /^(?:txt|[px]?html?|xml)$/) &&
	   ($ctype !~ m@^(?:text/(?:plain|[px]?html?|english|sgml|xml|enriched|richtext)|message/external-body)@)) ||

	  # image
	  (($name =~ /^(?:jpe?g|tiff?|gif|png)$/) &&
	   ($ctype !~ m@^(?:image/|application/mac-binhex)@)) ||

	  # vcard
	  (($name eq "vcf") && $ctype ne "text/vcard") ||

	  # application
	  (($name =~ /^(?:bat|com|exe|pif|scr|swf|vbs)$/) &&
	   ($ctype !~ m@^application/@)) ||

	  # msword
	  (($name eq "doc") && ($ctype !~ m@^application/.*word$@)) ||

	  # powerpoint
	  (($name eq "ppt") &&
	   ($ctype !~ m@^application/.*(?:powerpoint|ppt)$@)) ||

	  # excel
	  (($name eq "xls") && ($ctype !~ m@^application/.*excel$@))
	  )
      {
	$pms->{antivirus_suspect_name} = 1;
      }
    }
  }
}

1;
