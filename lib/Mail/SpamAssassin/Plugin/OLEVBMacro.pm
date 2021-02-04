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

Mail::SpamAssassin::Plugin::OLEVBMacro - search attached documents for evidence of containing an OLE Macro

=head1 SYNOPSIS

  loadplugin Mail::SpamAssassin::Plugin::OLEVBMacro

  ifplugin Mail::SpamAssassin::Plugin::OLEVBMacro
    body     OLEMACRO eval:check_olemacro()
    describe OLEMACRO Attachment has an Office Macro

    body     OLEMACRO_MALICE eval:check_olemacro_malice()
    describe OLEMACRO_MALICE Potentially malicious Office Macro

    body     OLEMACRO_ENCRYPTED eval:check_olemacro_encrypted()
    describe OLEMACRO_ENCRYPTED Has an Office doc that is encrypted

    body     OLEMACRO_RENAME eval:check_olemacro_renamed()
    describe OLEMACRO_RENAME Has an Office doc that has been renamed

    body     OLEMACRO_ZIP_PW eval:check_olemacro_zip_password()
    describe OLEMACRO_ZIP_PW Has an Office doc that is password protected in a zip

    body     OLEMACRO_CSV eval:check_olemacro_csv()
    describe OLEMACRO_CSV Malicious csv file that tries to exec cmd.exe detected

    body     OLEMACRO_DOWNLOAD_EXE eval:check_olemacro_download_exe()
    describe OLEMACRO_DOWNLOAD_EXE Malicious code inside the Office doc that tries to download a .exe file detected
  endif

=head1 DESCRIPTION

This plugin detects OLE Macro inside documents attached to emails.
It can detect documents inside zip files as well as encrypted documents.

=head1 REQUIREMENT

This plugin requires Archive::Zip and IO::String perl modules.

=head1 USER PREFERENCES

The following options can be used in both site-wide (C<local.cf>) and
user-specific (C<user_prefs>) configuration files to customize how
the module handles attached documents

=cut

package Mail::SpamAssassin::Plugin::OLEVBMacro;
use strict;
use warnings;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Util qw(compile_regexp);

use constant HAS_ARCHIVE_ZIP => eval { require Archive::Zip; };
use constant HAS_IO_STRING => eval { require IO::String; };

BEGIN
{
    eval{
      import Archive::Zip qw( :ERROR_CODES :CONSTANTS )
    };
    eval{
      import  IO::String
    };
}

use re 'taint';

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

our $VERSION = '0.52';

# https://www.openoffice.org/sc/compdocfileformat.pdf
# http://blog.rootshell.be/2015/01/08/searching-for-microsoft-office-files-containing-macro/
my $marker1 = "\xd0\xcf\x11\xe0";
my $marker2 = "\x00\x41\x74\x74\x72\x69\x62\x75\x74\x00";
# Office 2003 embedded ole
my $marker2a = "\x01\x00\x4f\x00\x6c\x00\x65\x00\x31\x00\x30\x00\x4e\x00\x61\x00";
# embedded object in rtf files (https://www.biblioscape.com/rtf15_spec.htm)
my $marker3 = "\x5c\x6f\x62\x6a\x65\x6d\x62";
my $marker4 = "\x5c\x6f\x62\x6a\x64\x61\x74";
my $marker5 = "\x5c\x20\x6f\x62\x6a\x64\x61\x74";
# Excel .xlsx encrypted package, thanks to Dan Bagwell for the sample
my $encrypted_marker = "\x45\x00\x6e\x00\x63\x00\x72\x00\x79\x00\x70\x00\x74\x00\x65\x00\x64\x00\x50\x00\x61\x00\x63\x00\x6b\x00\x61\x00\x67\x00\x65";
# .exe file downloaded from external website
my $exe_marker1 = "\x00((https?)://)[-A-Za-z0-9+&@#/%?=~_|!:,.;]{5,1000}[-A-Za-z0-9+&@#/%=~_|]{5,1000}(\.exe|\.cmd|\.bat)([\x06|\x00])";
my $exe_marker2 = "URLDownloadToFileA";

# this code burps an ugly message if it fails, but that's redirected elsewhere
# AZ_OK is a constant exported by Archive::Zip
my $az_ok;
eval '$az_ok = AZ_OK';

# constructor: register the eval rule
sub new {
  my $class = shift;
  my $mailsaobject = shift;

  # some boilerplate...
  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->set_config($mailsaobject->{conf});

  $self->register_eval_rule("check_olemacro");
  $self->register_eval_rule("check_olemacro_csv");
  $self->register_eval_rule("check_olemacro_malice");
  $self->register_eval_rule("check_olemacro_renamed");
  $self->register_eval_rule("check_olemacro_encrypted");
  $self->register_eval_rule("check_olemacro_zip_password");
  $self->register_eval_rule("check_olemacro_download_exe");

  return $self;
}

sub dbg {
  Mail::SpamAssassin::Plugin::dbg ("OLEVBMacro: @_");
}

sub set_config {
  my ($self, $conf) = @_;
  my @cmds = ();

  push(@cmds, {
    setting => 'olemacro_num_mime',
    default => 5,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });

=over 4

=item olemacro_num_mime (default: 5)

Configure the maximum number of matching MIME parts the plugin will scan

=back

=cut

  push(@cmds, {
    setting => 'olemacro_num_zip',
    default => 8,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });

=over 4

=item olemacro_num_zip (default: 8)

Configure the maximum number of matching zip members the plugin will scan

=back

=cut

  push(@cmds, {
    setting => 'olemacro_zip_depth',
    default => 2,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });

=over 4

=item olemacro_zip_depth (default: 2)

Depth to recurse within Zip files

=back

=cut

  push(@cmds, {
    setting => 'olemacro_extended_scan',
    default => 0,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL,
  });

=over 4

=item olemacro_extended_scan ( 0 | 1 ) (default: 0)

Scan more files for potential macros, the C<olemacro_skip_exts> parameter will still be honored.
This parameter is off by default, this option is needed only to run
C<eval:check_olemacro_renamed> rule.
If this is turned on consider adjusting values for C<olemacro_num_mime> and C<olemacro_num_zip>
and prepare for more CPU overhead

=back

=cut

  push(@cmds, {
    setting => 'olemacro_prefer_contentdisposition',
    default => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL,
  });

=over 4

=item olemacro_prefer_contentdisposition ( 0 | 1 ) (default: 1)

Choose if the content-disposition header filename be preferred if ambiguity is encountered whilst trying to get filename

=back

=cut

  push(@cmds, {
    setting => 'olemacro_max_file',
    default => 1024000,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });

=over 4

=item olemacro_max_file (default: 1024000)

Configure the largest file that the plugin will decode from the MIME objects

=back

=cut

  # https://blogs.msdn.microsoft.com/vsofficedeveloper/2008/05/08/office-2007-file-format-mime-types-for-http-content-streaming-2/
  # https://technet.microsoft.com/en-us/library/ee309278(office.12).aspx

  push(@cmds, {
    setting => 'olemacro_exts',
    default => qr/(?:doc|docx|dot|pot|ppa|pps|ppt|rtf|sldm|xl|xla|xls|xlsx|xlt|xltx|xslb)$/,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (defined $value && $value !~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      my ($rec, $err) = compile_regexp($value, 0);
      if (!$rec) {
       dbg("config: invalid olemacro_exts '$value': $err");
       return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      $self->{olemacro_exts} = $rec;
      },
    }
  );

=over 4

=item olemacro_exts (default: (?:doc|docx|dot|pot|ppa|pps|ppt|rtf|sldm|xl|xla|xls|xlsx|xlt|xltx|xslb)$)

Set the case-insensitive regexp used to configure the extensions the plugin
targets for macro scanning

=back

=cut

  push(@cmds, {
    setting => 'olemacro_macro_exts',
    default => qr/(?:docm|dotm|ppam|potm|ppst|ppsm|pptm|sldm|xlm|xlam|xlsb|xlsm|xltm|xltx|xps)$/,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (defined $value && $value !~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      my ($rec, $err) = compile_regexp($value, 0);
      if (!$rec) {
       dbg("config: invalid olemacro_macro_exts '$value': $err");
       return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      $self->{olemacro_macro_exts} = $rec;
    },
  });

=over 4

=item olemacro_macro_exts (default: (?:docm|dotm|ppam|potm|ppst|ppsm|pptm|sldm|xlm|xlam|xlsb|xlsm|xltm|xltx|xps)$)

Set the case-insensitive regexp used to configure the extensions the plugin
treats as containing a macro

=back

=cut

  push(@cmds, {
    setting => 'olemacro_skip_exts',
    default => qr/(?:dotx|potx|ppsx|pptx|sldx)$/,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (defined $value && $value !~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      my ($rec, $err) = compile_regexp($value, 0);
      if (!$rec) {
       dbg("config: invalid olemacro_skip_exts '$value': $err");
       return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }

      $self->{olemacro_skip_exts} = $rec;
    },
  });

=over 4

=item olemacro_skip_exts (default: (?:dotx|potx|ppsx|pptx|sldx|xltx)$)

Set the case-insensitive regexp used to configure extensions for the plugin
to skip entirely, these should only be guaranteed macro free files

=back

=cut

  push(@cmds, {
    setting => 'olemacro_skip_ctypes',
    default => qr/^(?:text\/)/,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (defined $value && $value !~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      my ($rec, $err) = compile_regexp($value, 0);
      if (!$rec) {
       dbg("config: invalid olemacro_skip_ctypes '$value': $err");
       return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }

      $self->{olemacro_skip_ctypes} = $rec;
    },
  });

=over 4

=item olemacro_skip_ctypes (default: ^(?:text\/))

Set the case-insensitive regexp used to configure content types for the
plugin to skip entirely, these should only be guaranteed macro free

=back

=cut

  push(@cmds, {
    setting => 'olemacro_zips',
    default => qr/(?:zip)$/,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (defined $value && $value !~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      my ($rec, $err) = compile_regexp($value, 0);
      if (!$rec) {
       dbg("config: invalid olemacro_zips '$value': $err");
       return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }

      $self->{olemacro_zips} = $rec;
    },
  });

=over 4

=item olemacro_zips (default: (?:zip)$)

Set the case-insensitive regexp used to configure extensions for the plugin
to target as zip files, files listed in configs above are also tested for zip

=back

=cut

  $conf->{parser}->register_commands(\@cmds);
}

sub check_olemacro {
  my ($self,$pms,$body,$name) = @_;

  _check_attachments(@_) unless exists $pms->{olemacro_exists};

  return $pms->{olemacro_exists};
}

sub check_olemacro_csv {
  my ($self,$pms,$body,$name) = @_;

  my $chunk_size = $pms->{conf}->{olemacro_max_file};

  foreach my $part ($pms->{msg}->find_parts(qr/./, 1)) {

    next unless ($part->{type} eq "text/plain");

    my ($ctt, $ctd, $cte, $name) = _get_part_details($pms, $part);
    next unless defined $ctt;

    next if $name eq '';

    # we skipped what we need/want to
    my $data = undef;

    # if name extension is csv - return true
    if ($name =~ /\.csv/i) {
      dbg("Found csv file with name $name");
      $data = $part->decode($chunk_size) unless defined $data;
      if($data =~ /MSEXCEL\|.{1,20}Windows\\System32\\cmd\.exe/) {
        $pms->{olemacro_csv} = 1;
      }
    }
  }
  return $pms->{olemacro_csv};
}

sub check_olemacro_malice {
  my ($self,$pms,$body,$name) = @_;

  _check_attachments(@_) unless exists $pms->{olemacro_malice};

  return $pms->{olemacro_malice};
}

sub check_olemacro_renamed {
  my ($self,$pms,$body,$name) = @_;

  _check_attachments(@_) unless exists $pms->{olemacro_renamed};

  if ( $pms->{olemacro_renamed} == 1 ) {
    dbg("Found Office document with a renamed macro");
  }

  return $pms->{olemacro_renamed};
}

sub check_olemacro_encrypted {
  my ($self,$pms,$body,$name) = @_;

  _check_attachments(@_) unless exists $pms->{olemacro_encrypted};

  return $pms->{olemacro_encrypted};
}

sub check_olemacro_zip_password {
  my ($self,$pms,$body,$name) = @_;

  _check_attachments(@_) unless exists $pms->{olemacro_zip_password};

  return $pms->{olemacro_zip_password};
}

sub check_olemacro_download_exe {
  my ($self,$pms,$body,$name) = @_;

  _check_attachments(@_) unless exists $pms->{olemacro_download_exe};

  return $pms->{olemacro_download_exe};
}

sub _check_attachments {

  my ($self,$pms,$body,$name) = @_;

  my $mimec = 0;
  my $chunk_size = $pms->{conf}->{olemacro_max_file};

  $pms->{olemacro_exists} = 0;
  $pms->{olemacro_malice} = 0;
  $pms->{olemacro_renamed} = 0;
  $pms->{olemacro_encrypted} = 0;
  $pms->{olemacro_zip_password} = 0;
  $pms->{olemacro_office_xml} = 0;

  foreach my $part ($pms->{msg}->find_parts(qr/./, 1)) {

    next if ($part->{type} =~ /$pms->{conf}->{olemacro_skip_ctypes}/i);

    my ($ctt, $ctd, $cte, $name) = _get_part_details($pms, $part);
    next unless defined $ctt;

    next if $name eq '';
    next if ($name =~ /$pms->{conf}->{olemacro_skip_exts}/i);

    # we skipped what we need/want to
    my $data = undef;

    # if name is macrotype - return true
    if ($name =~ /$pms->{conf}->{olemacro_macro_exts}/i) {
      dbg("Found macrotype attachment with name $name");
      $pms->{olemacro_exists} = 1;

      $data = $part->decode($chunk_size) unless defined $data;

      if (defined $data) {
        _check_encrypted_doc($pms, $name, $data);
        _check_macrotype_doc($pms, $name, $data);
      }

      return 1 if $pms->{olemacro_exists} == 1;
    }

    # if name is ext type - check and return true if needed
    if ($name =~ /$pms->{conf}->{olemacro_exts}/i) {
      dbg("Found attachment with name $name");
      $data = $part->decode($chunk_size) unless defined $data;

      if (defined $data) {
        _check_encrypted_doc($pms, $name, $data);
        _check_oldtype_doc($pms, $name, $data);
        # zipped doc that matches olemacro_exts - strange
        if (_check_macrotype_doc($pms, $name, $data)) {
          $pms->{olemacro_renamed} = $pms->{olemacro_office_xml};
        }
      }

      return 1 if $pms->{olemacro_exists} == 1;
    }

    if ($name =~ /$pms->{conf}->{olemacro_zips}/i) {
      dbg("Found zip attachment with name $name");
      $data = $part->decode($chunk_size) unless defined $data;

      if (defined $data) {
        _check_zip($pms, $name, $data);
      }

      return 1 if $pms->{olemacro_exists} == 1;
    }

    if ((defined $data) and ($data =~ /$exe_marker1/) and (index($data, $exe_marker2))) {
      dbg('Url that triggers a download to an .exe file found in Office file');
      $pms->{olemacro_download_exe} = 1;
    }

    if ($pms->{conf}->{olemacro_extended_scan} == 1) {
      dbg("Extended scan attachment with name $name");
      $data = $part->decode($chunk_size) unless defined $data;

      if (defined $data) {
        if (_is_office_doc($data)) {
          $pms->{olemacro_renamed} = 1;
          dbg("Found $name to be an Office Doc!");
          _check_encrypted_doc($pms, $name, $data);
          _check_oldtype_doc($pms, $name, $data);
        }

        if (_check_macrotype_doc($pms, $name, $data)) {
          $pms->{olemacro_renamed} = $pms->{olemacro_office_xml};
        }

        _check_zip($pms, $name, $data);
      }

      return 1 if $pms->{olemacro_exists} == 1;
    }

    # if we get to here with data a part has been scanned nudge as reqd
    $mimec+=1 if defined $data;
    if ($mimec >= $pms->{conf}->{olemacro_num_mime}) {
      dbg('MIME limit reached');
      last;
    }
  dbg("No Marker of a Macro found in file $name");
  }
  return 0;
}

sub _check_zip {
  my ($pms, $name, $data, $depth) = @_;

  if (!HAS_ARCHIVE_ZIP) {
    warn "check_zip not supported, required module Archive::Zip missing\n";
    return 0;
  }
  return 0 if $pms->{conf}->{olemacro_num_zip} == 0;

  $depth = $depth || 1;
  return 0 if ($depth > $pms->{conf}->{olemacro_zip_depth});

  return 0 unless _is_zip_file($name, $data);
  my $zip = _open_zip_handle($data);
  return 0 unless $zip;

  dbg("Zip opened");

  my $filec = 0;
  my @members = $zip->members();
  # foreach zip member
  # - skip if in skip exts
  # - return 1 if in macro types
  # - check for marker if doc type
  # - check if a zip
  foreach my $member (@members){
    my $mname = lc $member->fileName();
    next if ($mname =~ /$pms->{conf}->{olemacro_skip_exts}/i);

    my $data = undef;
    my $status = undef;

    # if name is macrotype - return true
    if ($mname =~ /$pms->{conf}->{olemacro_macro_exts}/i) {
      dbg("Found macrotype zip member $mname");
      $pms->{olemacro_exists} = 1;

      if ($member->isEncrypted()) {
        dbg("Zip member $mname is encrypted (zip pw)");
        $pms->{olemacro_zip_password} = 1;
        return 1;
      }

      ( $data, $status ) = $member->contents() unless defined $data;
      return 1 unless $status == $az_ok;

      _check_encrypted_doc($pms, $name, $data);
      _check_macrotype_doc($pms, $name, $data);

      return 1 if $pms->{olemacro_exists} == 1;
    }

    if ($mname =~ /$pms->{conf}->{olemacro_exts}/i) {
      dbg("Found zip member $mname");

      if ($member->isEncrypted()) {
        dbg("Zip member $mname is encrypted (zip pw)");
        $pms->{olemacro_zip_password} = 1;
        next;
      }

      ( $data, $status ) = $member->contents() unless defined $data;
      next unless $status == $az_ok;


      _check_encrypted_doc($pms, $name, $data);
      _check_oldtype_doc($pms, $name, $data);
      # zipped doc that matches olemacro_exts - strange
      if (_check_macrotype_doc($pms, $name, $data)) {
        $pms->{olemacro_renamed} = $pms->{olemacro_office_xml};
      }

      return 1 if $pms->{olemacro_exists} == 1;

    }

    if ($mname =~ /$pms->{conf}->{olemacro_zips}/i) {
      dbg("Found zippy zip member $mname");
      ( $data, $status ) = $member->contents() unless defined $data;
      next unless $status == $az_ok;

      _check_zip($pms, $name, $data, $depth);

      return 1 if $pms->{olemacro_exists} == 1;

    }

    if ($pms->{conf}->{olemacro_extended_scan} == 1) {
      dbg("Extended scan attachment with member name $mname");
      ( $data, $status ) = $member->contents() unless defined $data;
      next unless $status == $az_ok;

      if (_is_office_doc($data)) {
        dbg("Found $name to be an Office Doc!");
        _check_encrypted_doc($pms, $name, $data);
        $pms->{olemacro_renamed} = 1;
        _check_oldtype_doc($pms, $name, $data);
      }

      if (_check_macrotype_doc($pms, $name, $data)) {
        $pms->{olemacro_renamed} = $pms->{olemacro_office_xml};
      }

      _check_zip($pms, $name, $data, $depth);

      return 1 if $pms->{olemacro_exists} == 1;

    }

    # if we get to here with data a member has been scanned nudge as reqd
    $filec+=1 if defined $data;
    if ($filec >= $pms->{conf}->{olemacro_num_zip}) {
      dbg('Zip limit reached');
      last;
    }
  }
  return 0;
}

sub _get_part_details {
    my ($pms, $part) = @_;
    #https://en.wikipedia.org/wiki/MIME#Content-Disposition
    #https://github.com/mikel/mail/pull/464

    my $ctt = $part->get_header('content-type');
    return undef unless defined $ctt; ## no critic (ProhibitExplicitReturnUndef)

    my $cte = lc($part->get_header('content-transfer-encoding') || '');
    return undef unless ($cte =~ /^(?:base64|quoted\-printable)$/); ## no critic (ProhibitExplicitReturnUndef)

    $ctt = _decode_part_header($part, $ctt || '');

    my $name = '';
    my $cttname = '';
    my $ctdname = '';

    if($ctt =~ m/(?:file)?name\s*=\s*["']?([^"';]*)["']?/is){
      $cttname = $1;
      $cttname =~ s/\s+$//;
    }

    my $ctd = $part->get_header('content-disposition');
    $ctd = _decode_part_header($part, $ctd || '');

    if($ctd =~ m/filename\s*=\s*["']?([^"';]*)["']?/is){
      $ctdname = $1;
      $ctdname =~ s/\s+$//;
    }

    if (lc $ctdname eq lc $cttname) {
      $name = $ctdname;
    } elsif ($ctdname eq '') {
      $name = $cttname;
    } elsif ($cttname eq '') {
      $name = $ctdname;
    } else {
      if ($pms->{conf}->{olemacro_prefer_contentdisposition}) {
        $name = $ctdname;
      } else {
        $name = $cttname;
      }
    }

    return $ctt, $ctd, $cte, lc $name;
}

sub _open_zip_handle {
  my ($data) = @_;
  # open our archive from raw data
  my $SH = IO::String->new($data);

  Archive::Zip::setErrorHandler( \&_zip_error_handler );
  my $zip = Archive::Zip->new();
  if($zip->readFromFileHandle( $SH ) != $az_ok){
    dbg("cannot read zipfile");
    # as we cannot read it its not a zip (or too big/corrupted)
    # so skip processing.
    return 0;
  }
  return $zip;
}

sub _check_macrotype_doc {
  my ($pms, $name, $data) = @_;

  if (!HAS_IO_STRING) {
    warn "check_macrotype_doc not supported, required module IO::String missing\n";
    return 0;
  }
  return 0 unless _is_zip_file($name, $data);

  my $zip = _open_zip_handle($data);
  return 0 unless $zip;

  # https://www.decalage.info/vba_tools
  # Consider macrofiles as lowercase, they are checked later with a case-insensitive method
  my %macrofiles = (
    'word/vbaproject.bin' => 'word2k7',
    'macros/vba/_vba_project' => 'word97',
    'xl/vbaproject.bin' => 'xl2k7',
    '_vba_project_cur/vba/_vba_project' => 'xl97',
    'ppt/vbaproject.bin' => 'ppt2k7',
  );

  my @members = $zip->members();
  foreach my $member (@members){
    my $mname = lc $member->fileName();
    if (exists($macrofiles{lc($mname)})) {
      dbg("Found $macrofiles{$mname} vba file");
      $pms->{olemacro_exists} = 1;
      last;
    }
  }

  # Look for a member named [Content_Types].xml and do checks
  if (my $ctypesxml = $zip->memberNamed('[Content_Types].xml')) {
    dbg('Found [Content_Types].xml file');
    $pms->{olemacro_office_xml} = 1;
    if (!$pms->{olemacro_exists}) {
      my ( $data, $status ) = $ctypesxml->contents();

      if (($status == $az_ok) && (_check_ctype_xml($data))) {
        $pms->{olemacro_exists} = 1;
      }
    }
  }

  if (($pms->{olemacro_exists}) && (_find_malice_bins($zip))) {
    $pms->{olemacro_malice} = 1;
  }

  return $pms->{olemacro_exists};

}

# Office 2003

sub _check_oldtype_doc {
  my ($pms, $name, $data) = @_;

  if (_check_markers($data)) {
    $pms->{olemacro_exists} = 1;
    if (_check_malice($data)) {
     $pms->{olemacro_malice} = 1;
    }
    return 1;
  }
}

# Encrypted doc

sub _check_encrypted_doc {
  my ($pms, $name, $data) = @_;

  if (_is_encrypted_doc($data)) {
    dbg("File $name is encrypted");
    $pms->{olemacro_encrypted} = 1;
  }

  return $pms->{olemacro_encrypted};
}

sub _is_encrypted_doc {
  my ($data) = @_;

  #http://stackoverflow.com/questions/14347513/how-to-detect-if-a-word-document-is-password-protected-before-uploading-the-file/14347730#14347730
  if (_is_office_doc($data)) {
    if ($data =~ /(?:<encryption xmlns)/i) {
      return 1;
    }
    if (index($data, "\x13") == 523) {
      return 1;
    }
    if (index($data, "\x2f") == 532) {
      return 1;
    }
    if (index($data, "\xfe") == 520) {
      return 1;
    }
    my $tdata = substr $data, 2000;
    $tdata =~ s/\\0/ /g;
    if (index($tdata, "E n c r y p t e d P a c k a g e") > -1) {
      return 1;
    }
    if (index($tdata, $encrypted_marker) > -1) {
      return 1;
    }
  }
}

sub _is_office_doc {
  my ($data) = @_;
  if (index($data, $marker1) == 0) {
    return 1;
  }
}

sub _is_zip_file {
  my ($name, $data) = @_;
  if (index($data, 'PK') == 0) {
    return 1;
  } else {
    return($name =~ /(?:zip)$/i);
  }
}

sub _check_markers {
  my ($data) = @_;

  if (index($data, $marker1) == 0 && index($data, $marker2) > -1) {
    dbg('Marker 1 & 2 found');
    return 1;
  }

  if (index($data, $marker1) == 0 && index($data, $marker2a) > -1) {
    dbg('Marker 1 & 2a found');
    return 1;
  }

  if (index($data, $marker3) > -1) {
    dbg('Marker 3 found');
    return 1;
  }

  if (index($data, $marker4) > -1) {
    dbg('Marker 4 found');
    return 1;
  }

  if (index($data, $marker5) > -1) {
    dbg('Marker 5 found');
    return 1;
  }

  if (index($data, 'w:macrosPresent="yes"') > -1) {
    dbg('XML macros marker found');
    return 1;
  }

  if (index($data, 'vbaProject.bin.rels') > -1) {
    dbg('XML macros marker found');
    return 1;
  }

}

sub _find_malice_bins {
  my ($zip) = @_;

  my @binfiles = $zip->membersMatching( '.*\.bin' );

  foreach my $member (@binfiles){
    my ( $data, $status ) = $member->contents();
    next unless $status == $az_ok;
    if (_check_malice($data)) {
      return 1;
    }
  }
}

sub _check_malice {
  my ($data) = @_;

  # https://www.greyhathacker.net/?p=872
  if ($data =~ /(?:document|auto|workbook)_?open/i) {
    dbg('Found potential malicious code');
    return 1;
  }
}

sub _check_ctype_xml {
  my ($data) = @_;

  # http://download.microsoft.com/download/D/3/3/D334A189-E51B-47FF-B0E8-C0479AFB0E3C/[MS-OFFMACRO].pdf
  if ($data =~ /ContentType=["']application\/vnd\.ms-office\.vbaProject["']/i){
    dbg('Found VBA ref');
    return 1;
  }
  if ($data =~ /macroEnabled/i) {
    dbg('Found Macro Ref');
    return 1;
  }
  if ($data =~ /application\/vnd\.ms-excel\.(?:intl)?macrosheet/i) {
    dbg('Excel macrosheet found');
    return 1;
  }
}

sub _zip_error_handler {
 1;
}

sub _decode_part_header {
  my($part, $header_field_body) = @_;

  return '' unless defined $header_field_body && $header_field_body ne '';

  # deal with folding and cream the newlines and such
  $header_field_body =~ s/\n[ \t]+/\n /g;
  $header_field_body =~ s/\015?\012//gs;

  local($1,$2,$3);

  # Multiple encoded sections must ignore the interim whitespace.
  # To avoid possible FPs with (\s+(?==\?))?, look for the whole RE
  # separated by whitespace.
  1 while $header_field_body =~
            s{ ( = \? [A-Za-z0-9_-]+ \? [bqBQ] \? [^?]* \? = ) \s+
               ( = \? [A-Za-z0-9_-]+ \? [bqBQ] \? [^?]* \? = ) }
             {$1$2}xsg;

  # transcode properly encoded RFC 2047 substrings into UTF-8 octets,
  # leave everything else unchanged as it is supposed to be UTF-8 (RFC 6532)
  # or plain US-ASCII
  $header_field_body =~
    s{ (?: = \? ([A-Za-z0-9_-]+) \? ([bqBQ]) \? ([^?]*) \? = ) }
     { $part->__decode_header($1, uc($2), $3) }xsge;

  return $header_field_body;
}

1;
