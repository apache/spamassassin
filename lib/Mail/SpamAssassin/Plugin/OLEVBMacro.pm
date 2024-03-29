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

Mail::SpamAssassin::Plugin::OLEVBMacro - scan Office documents for evidence of OLE Macros or other exploits

=head1 SYNOPSIS

  loadplugin Mail::SpamAssassin::Plugin::OLEVBMacro

  ifplugin Mail::SpamAssassin::Plugin::OLEVBMacro
    body     OLEMACRO eval:check_olemacro()
    describe OLEMACRO Attachment has an Office Macro

    body     OLEOBJ eval:check_oleobject()
    describe OLEOBJ Attachment has an Ole Object

    body     OLERTF eval:check_olertfobject()
    describe OLERTF Attachment has an Ole Rtf Object

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

    body     OLEMACRO_URI_TARGET eval:check_olemacro_redirect_uri()
    describe OLEMACRO_URI_TARGET Uri inside an Office doc

    body     OLEMACRO_MHTML_TARGET eval:check_olemacro_mhtml_uri()
    describe OLEMACRO_MHTML_TARGET Exploitable mhtml uri inside an Office doc
  endif

=head1 DESCRIPTION

This plugin detects OLE Macros or other exploits inside Office documents
attached to emails.  It can detect documents inside zip files as well as
encrypted documents.

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
use Mail::SpamAssassin::Util qw(compile_regexp get_part_details);

use constant HAS_ARCHIVE_ZIP => eval { require Archive::Zip; };
use constant HAS_IO_STRING => eval { require IO::String; };

BEGIN
{
    eval{
      Archive::Zip->import(qw( :ERROR_CODES :CONSTANTS ))
    };
    eval{
      IO::String->import
    };
}

use re 'taint';

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

our $VERSION = '4.00';

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
# Excel .xls marker present only on unencrypted files
my $workbook_marker = "\x57\x00\x6f\x00\x72\x00\x6b\x00\x62\x00\x6f\x00\x6f\x00\x6b\x00";
# .exe file downloaded from external website
my $exe_marker1 = "\x00(https?://[-a-z0-9+&@#/%?=~_|!:,.;]{5,1000}[-a-z0-9+&@#/%=~_|]{5,1000}\.(?:exe|cmd|bat))[\x06|\x00]";
my $exe_marker2 = "URLDownloadToFileA";

# CVE-2021-40444 marker
my $mhtml_marker1 = "^MHTML:&#x48;&#x54;&#x50;&#x3a;&#x5c;&#x5c;&#x31;&";
my $mhtml_marker2 = "^mhtml:https?://";

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

  $self->register_eval_rule("check_olemacro", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule("check_oleobject", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule("check_olertfobject", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule("check_olemacro_csv", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule("check_olemacro_malice", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule("check_olemacro_renamed", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule("check_olemacro_encrypted", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule("check_olemacro_zip_password", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule("check_olemacro_download_exe", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule("check_olemacro_redirect_uri", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);
  $self->register_eval_rule("check_olemacro_mhtml_uri", $Mail::SpamAssassin::Conf::TYPE_BODY_EVALS);

  # lower priority for add_uri_detail_list to work
  $self->register_method_priority ("parsed_metadata", -1);

  if (!HAS_ARCHIVE_ZIP) {
    warn "OLEVBMacro: check_zip not supported, required module Archive::Zip missing\n";
  }
  if (!HAS_IO_STRING) {
    warn "OLEVBMacro: check_macrotype_doc not supported, required module IO::String missing\n";
  }

  return $self;
}

sub dbg { my $msg = shift; Mail::SpamAssassin::Plugin::dbg("OLEVBMacro: $msg", @_); }

sub set_config {
  my ($self, $conf) = @_;
  my @cmds = ();

=over 4

=item olemacro_num_mime (default: 5)

Configure the maximum number of matching MIME parts (attachments) the plugin
will scan.

=back

=cut

  push(@cmds, {
    setting => 'olemacro_num_mime',
    default => 5,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });

=over 4

=item olemacro_num_zip (default: 8)

Configure the maximum number of matching files inside the zip to scan.
To disable zip scanning, set 0.

=back

=cut

  push(@cmds, {
    setting => 'olemacro_num_zip',
    default => 8,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });

=over 4

=item olemacro_zip_depth (default: 2)

Depth to recurse within zip files.

=back

=cut

  push(@cmds, {
    setting => 'olemacro_zip_depth',
    default => 2,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });

=over 4

=item olemacro_extended_scan ( 0 | 1 ) (default: 0)

Scan all files for potential office files and/or macros, the
C<olemacro_skip_exts> parameter will still be honored.  This parameter is
off by default, this option is needed only to run
C<eval:check_olemacro_renamed> rule.  If this is turned on consider
adjusting values for C<olemacro_num_mime> and C<olemacro_num_zip> and
prepare for more CPU overhead.

=back

=cut

  push(@cmds, {
    setting => 'olemacro_extended_scan',
    default => 0,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL,
  });

=over 4

=item olemacro_prefer_contentdisposition ( 0 | 1 ) (default: 1)

Choose if the content-disposition header filename be preferred if ambiguity is encountered whilst trying to get filename.

=back

=cut

  push(@cmds, {
    setting => 'olemacro_prefer_contentdisposition',
    default => 1,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_BOOL,
  });

=over 4

=item olemacro_max_file (default: 1024000)

Limit the amount of bytes that the plugin will decode and scan from the MIME
objects (attachments).

=back

=cut

  push(@cmds, {
    setting => 'olemacro_max_file',
    default => 1024000,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });

=over 4

=item olemacro_exts (default: (?:doc|docx|dot|pot|ppa|pps|ppt|rtf|sldm|xl|xla|xls|xlsx|xlt|xltx|xslb)$)

Set the case-insensitive regexp used to configure the extensions the plugin
targets for macro scanning.

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
  });

=over 4

=item olemacro_macro_exts (default: (?:docm|dotm|ppam|potm|ppst|ppsm|pptm|sldm|xlm|xlam|xlsb|xlsm|xltm|xps)$)

Set the case-insensitive regexp used to configure the extensions the plugin
treats as containing a macro.

=back

=cut

  push(@cmds, {
    setting => 'olemacro_macro_exts',
    default => qr/(?:docm|dotm|ppam|potm|ppst|ppsm|pptm|sldm|xlm|xlam|xlsb|xlsm|xltm|xps)$/,
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

=item olemacro_skip_exts (default: (?:dotx|potx|ppsx|pptx|sldx)$)

Set the case-insensitive regexp used to configure extensions for the plugin
to skip entirely, these should only be guaranteed macro free files.

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

=item olemacro_skip_ctypes (default: ^(?:text\/))

Set the case-insensitive regexp used to configure content types for the
plugin to skip entirely, these should only be guaranteed macro free.

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

=item olemacro_zips (default: (?:zip)$)

Set the case-insensitive regexp used to configure extensions for the plugin
to target as zip files, files listed in configs above are also tested for zip.

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

=item olemacro_download_marker (default: (?:cmd(?:\.exe)? \/c ms\^h\^ta ht\^tps?:\/\^\/))

Set the case-insensitive regexp used to match the script used to
download files from the Office document.

=back

=cut

  push(@cmds, {
    setting => 'olemacro_download_marker',
    default => qr/(?:cmd(?:\.exe)? \/c ms\^h\^ta ht\^tps?:\/\^\/)/,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_STRING,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (defined $value && $value !~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      my ($rec, $err) = compile_regexp($value, 0);
      if (!$rec) {
        dbg("config: invalid olemacro_download_marker '$value': $err");
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      $self->{olemacro_download_marker} = $rec;
    },
  });

  $conf->{parser}->register_commands(\@cmds);
}

sub parsed_metadata {
  my ($self, $opts) = @_;

  _check_attachments($opts->{permsgstatus});
}

sub check_olemacro {
  my ($self, $pms) = @_;

  return $pms->{olemacro_exists} ? 1 : 0;
}

sub check_oleobject {
  my ($self, $pms) = @_;

  return $pms->{oleobject_exists} ? 1 : 0;
}

sub check_olertfobject {
  my ($self, $pms) = @_;

  return $pms->{olertfobject_exists} ? 1 : 0;
}

sub check_olemacro_csv {
  my ($self, $pms) = @_;

  return $pms->{olemacro_csv} ? 1 : 0;
}

sub check_olemacro_malice {
  my ($self, $pms) = @_;

  return $pms->{olemacro_malice} ? 1 : 0;
}

sub check_olemacro_renamed {
  my ($self, $pms) = @_;

  return $pms->{olemacro_renamed} ? 1 : 0;
}

sub check_olemacro_encrypted {
  my ($self, $pms) = @_;

  return $pms->{olemacro_encrypted} ? 1 : 0;
}

sub check_olemacro_zip_password {
  my ($self, $pms) = @_;

  return $pms->{olemacro_zip_password} ? 1 : 0;
}

sub check_olemacro_download_exe {
  my ($self, $pms) = @_;

  return $pms->{olemacro_download_exe} ? 1 : 0;
}

sub check_olemacro_redirect_uri {
  my ($self, $pms) = @_;

  if (exists $pms->{olemacro_redirect_uri}) {
    my $rulename = $pms->get_current_eval_rule_name();
    $pms->test_log($_, $rulename) foreach (keys %{$pms->{olemacro_redirect_uri}});
    return 1;
  }

  return 0;
}

sub check_olemacro_mhtml_uri {
  my ($self, $pms) = @_;

  if (exists $pms->{olemacro_mhtml_uri}) {
    my $rulename = $pms->get_current_eval_rule_name();
    $pms->test_log($_, $rulename) foreach (keys %{$pms->{olemacro_mhtml_uri}});
    return 1;
  }

  return 0;
}

sub _check_attachments {
  my ($pms) = @_;

  my $conf = $pms->{conf};
  my $mimec = 0;

  foreach my $part ($pms->{msg}->find_parts(qr/./, 1)) {
    next if $part->{type} =~ /$conf->{olemacro_skip_ctypes}/i;

    my ($ctt, $ctd, $cte, $name) = get_part_details($pms, $part, $conf->{olemacro_prefer_contentdisposition});
    next unless defined $ctt;
    next if $name eq '';

    if ($name =~ /$conf->{olemacro_skip_exts}/i) {
      dbg("Skipping file \"$name\" (olemacro_skip_exts)");
      next;
    }

    my $data = $part->decode($conf->{olemacro_max_file});
    if (!defined $data || $data eq '') {
      dbg("Skipping empty file \"$name\"");
      next;
    }

    # csv
    if ($name =~ /\.csv$/i && $conf->{eval_to_rule}->{check_olemacro_csv}) {
      dbg("Checking csv file \"$name\" for exploits");
      _check_csv($pms, $name, $data);
    }

    # zip extensions
    if ($name =~ /$conf->{olemacro_zips}/i) {
      dbg("Found zip attachment with name \"$name\"");
      _check_zip($pms, $name, $data);
    }
    # macro extensions
    elsif ($name =~ /$conf->{olemacro_macro_exts}/i) {
      dbg("Found macrotype attachment with name \"$name\"");
      $pms->{olemacro_exists} = 1;
      _check_encrypted_doc($pms, $name, $data);
      _check_macrotype_doc($pms, $name, $data);
      _check_download_marker($pms, $name, $data);
    }
    # normal extensions
    elsif ($name =~ /$conf->{olemacro_exts}/i) {
      dbg("Found attachment with name \"$name\"");
      _check_encrypted_doc($pms, $name, $data);
      _check_oldtype_doc($pms, $name, $data);
      _check_macrotype_doc($pms, $name, $data);
      _check_download_marker($pms, $name, $data);
    }
    # other files, check for rename?
    elsif ($conf->{olemacro_extended_scan}) {
      dbg("Extended scan for file \"$name\"");
      my $renamed = 0;
      $renamed = 1 if _is_office_doc($data);
      $renamed = 1 if _check_encrypted_doc($pms, $name, $data);
      $renamed = 1 if _check_oldtype_doc($pms, $name, $data);
      $renamed = 1 if _check_macrotype_doc($pms, $name, $data);
      if ($renamed) {
        dbg("Found renamed office file \"$name\"");
        $pms->{olemacro_renamed} = 1;
        _check_download_marker($pms, $name, $data);
      }
      _check_zip($pms, $name, $data);
    }
    # nothing to check for this file
    else {
      next;
    }

    # something was checked, increment counter
    if (++$mimec >= $conf->{olemacro_num_mime}) {
      dbg('MIME limit reached');
      last;
    }
  }

  return 0;
}

sub _check_download_marker {
  my ($pms, $name, $data) = @_;

  return 0 unless $pms->{conf}->{eval_to_rule}->{check_olemacro_download_exe};

  if ((index($data, $exe_marker2) && $data =~ /$exe_marker1/i)
       || $data =~ /($pms->{conf}->{olemacro_download_marker})/i) {
    my $uri = defined $1 ? $1 : $2;
    dbg("Found URI that triggers a download in \"$name\": $uri");
    $pms->{olemacro_download_exe} = 1;
    return 1;
  }

  return 0;
}

sub _check_csv {
  my ($pms, $name, $data) = @_;

  if (index($data, 'cmd.exe') >= 0 &&
        $data =~ /MSEXCEL\|.{1,20}Windows\\System32\\cmd\.exe/) {
    dbg("Found cmd.exe exploit in \"$name\"");
    $pms->{olemacro_csv} = 1;
  }
}

sub _check_zip {
  my ($pms, $name, $data, $depth) = @_;

  return 0 if !$pms->{conf}->{olemacro_num_zip};

  if (++$depth > $pms->{conf}->{olemacro_zip_depth}) {
    dbg("Zip recursion limit exceeded");
    return 0;
  }

  return 0 if !defined $data || $data eq '';

  return 0 unless _is_zip_file($name, $data);
  my $zip = _open_zip_handle($data);
  return 0 unless defined $zip;

  dbg("Zip \"$name\" opened");

  my $conf = $pms->{conf};
  my $filec = 0;
  my @members = $zip->members();
  foreach my $member (@members) {
    my $name = $member->fileName();
    my $data; # open zip member lazily

    if ($name =~ /$conf->{olemacro_skip_exts}/i) {
      dbg("Skipping zip member \"$name\" (olemacro_skip_exts)");
      next;
    }

    if ($member->isEncrypted()) {
      if ($name =~ /$conf->{olemacro_macro_exts}/i) {
        dbg("Found macrotype zip member \"$name\"");
        $pms->{olemacro_exists} = 1;
      }
      dbg("Zip member \"$name\" is encrypted (zip pw)");
      $pms->{olemacro_zip_password} = 1;
      next;
    }

    # csv
    if ($name =~ /\.csv$/i && $conf->{eval_to_rule}->{check_olemacro_csv}) {
      dbg("Checking zipped csv file \"$name\" for exploits");
      if (!defined $data) {
        ($data, my $status) = $member->contents();
        $data = undef  unless $status == $az_ok;
      }
      _check_csv($pms, $name, $data) if defined $data;
    }

    # zip extensions
    if ($name =~ /$conf->{olemacro_zips}/i) {
      dbg("Found zippy zip member \"$name\"");
      if (!defined $data) {
        ($data, my $status) = $member->contents();
        $data = undef  unless $status == $az_ok;
      }
      _check_zip($pms, $name, $data, $depth) if defined $data;
    }
    # macro extensions
    elsif ($name =~ /$conf->{olemacro_macro_exts}/i) {
      dbg("Found macrotype zip member \"$name\"");
      $pms->{olemacro_exists} = 1;
      if (!defined $data) {
        ($data, my $status) = $member->contents();
        $data = undef  unless $status == $az_ok;
      }
      if (defined $data) {
        _check_encrypted_doc($pms, $name, $data);
        _check_macrotype_doc($pms, $name, $data);
        _check_download_marker($pms, $name, $data);
      }
    }
    # normal extensions
    elsif ($name =~ /$conf->{olemacro_exts}/i) {
      dbg("Found zip member \"$name\"");
      if (!defined $data) {
        ($data, my $status) = $member->contents();
        $data = undef  unless $status == $az_ok;
      }
      if (defined $data) {
        _check_encrypted_doc($pms, $name, $data);
        _check_oldtype_doc($pms, $name, $data);
        _check_macrotype_doc($pms, $name, $data);
        _check_download_marker($pms, $name, $data);
      }
    }
    # other files, check for rename?
    elsif ($conf->{olemacro_extended_scan}) {
      dbg("Extended scan for zip member \"$name\"");
      if (!defined $data) {
        ($data, my $status) = $member->contents();
        $data = undef  unless $status == $az_ok;
      }
      if (defined $data) {
        my $renamed = 0;
        $renamed = 1 if _is_office_doc($data);
        $renamed = 1 if _check_encrypted_doc($pms, $name, $data);
        $renamed = 1 if _check_oldtype_doc($pms, $name, $data);
        $renamed = 1 if _check_macrotype_doc($pms, $name, $data);
        if ($renamed) {
          dbg("Found renamed office file \"$name\"");
          $pms->{olemacro_renamed} = 1;
          _check_download_marker($pms, $name, $data);
        }
        _check_zip($pms, $name, $data, $depth);
      }
    }
    # nothing to check for this file
    else {
      next;
    }

    # something was checked, increment counter
    if (++$filec >= $conf->{olemacro_num_zip}) {
      dbg('Zip limit reached');
      last;
    }
  }

  return 1;
}

sub _open_zip_handle {
  my ($data) = @_;

  return unless HAS_ARCHIVE_ZIP && HAS_IO_STRING;

  # open our archive from raw data
  my $SH = IO::String->new($data);
  Archive::Zip::setErrorHandler(\&_zip_error_handler);
  my $zip = Archive::Zip->new();
  if ($zip->readFromFileHandle($SH) != $az_ok) {
    dbg("cannot read zipfile");
    # as we cannot read it its not a zip (or too big/corrupted)
    # so skip processing.
    return;
  }

  return $zip;
}

sub _check_macrotype_doc {
  my ($pms, $name, $data) = @_;

  return if !defined $data || $data eq '';

  return unless _is_zip_file($name, $data);
  my $zip = _open_zip_handle($data);
  return unless $zip;

  my $is_doc = 0;
  my $olemacro_exists = 0;

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
    my $name = lc $member->fileName();
    if (exists $macrofiles{$name}) {
      dbg("Found vba file \"$name\"");
      $is_doc = 1;
      $olemacro_exists = $pms->{olemacro_exists} = 1;
    }
    if (index($name, 'xl/embeddings/') == 0) {
      dbg("Found ole file \"$name\"");
      $is_doc = 1;
      $pms->{oleobject_exists} = 1;
    }
    if ($name =~ /^word\/.{1,50}\.rtf\b/) {
      dbg("Found ole rtf file \"$name\"");
      $is_doc = 1;
      $pms->{olertfobject_exists} = 1;
    }
  }

  # Look for a member named [Content_Types].xml and do checks
  if (my $ctypesxml = $zip->memberNamed('[Content_Types].xml')) {
    dbg('Found [Content_Types].xml file');
    $is_doc = 1;
    if (!$pms->{olemacro_exists}) {
      my ($data, $status) = $ctypesxml->contents();
      if ($status == $az_ok && _check_ctype_xml($data)) {
        $pms->{olemacro_exists} = 1;
      }
    }
  }

  my @rels = $zip->membersMatching('.*\.rels');
  foreach my $rel (@rels) {
    dbg("Found \"".$rel->fileName."\" configuration file");
    my ($data, $status) = $rel->contents();
    next unless $status == $az_ok;
    my @relations = split(/Relationship\s/, $data);
    $is_doc = 1 if @relations;
    foreach my $rl (@relations) {
      if ($rl =~ /Target=\"([^"]*)\".*?TargetMode=\"External\"/is) {
        my $uri = $1;
        if ($uri =~ /(?:$mhtml_marker1|$mhtml_marker2)/i) {
          dbg("Found target mhtml uri: $uri");
          if (keys %{$pms->{olemacro_mhtml_uri}} < 5) {
            $pms->{olemacro_mhtml_uri}{$uri} = 1;
          }
        }
        $uri =~ s/^mhtml://i;
        if ($uri =~ /^https?:\/\//i) {
          dbg("Found target uri: $uri");
          if (!exists $pms->{olemacro_redirect_uri}{$uri}) {
            if (keys %{$pms->{olemacro_redirect_uri}} < 10) {
              $pms->add_uri_detail_list($uri);
              $pms->{olemacro_redirect_uri}{$uri} = 1;
            }
          }
        }
      }
    }
  }

  if ($olemacro_exists && _find_malice_bins($zip)) {
    $pms->{olemacro_malice} = 1;
  }

  return $is_doc;
}

# Office 2003
sub _check_oldtype_doc {
  my ($pms, $name, $data) = @_;

  return 0 if !defined $data || $data eq '';

  if (_check_markers($data)) {
    $pms->{olemacro_exists} = 1;
    if (_check_malice($data)) {
      $pms->{olemacro_malice} = 1;
    }
    return 1;
  }

  return 0;
}

# Encrypted doc
sub _check_encrypted_doc {
  my ($pms, $name, $data) = @_;

  return 0 if !defined $data || $data eq '';

  if (_is_encrypted_doc($data)) {
    dbg("File \"$name\" is encrypted");
    $pms->{olemacro_encrypted} = 1;
    return 1;
  }

  return 0;
}

sub _is_encrypted_doc {
  my ($data) = @_;

  return 0 unless _is_office_doc($data);

  #http://stackoverflow.com/questions/14347513/how-to-detect-if-a-word-document-is-password-protected-before-uploading-the-file/14347730#14347730
  return 1 if $data =~ /(?:<encryption xmlns)/i;
  my $tdata = substr($data, 0, 2000);
  return 1 if index($tdata, $encrypted_marker) > -1;
  $tdata =~ s/\\0/ /g;
  return 1 if index($tdata, "E n c r y p t e d P a c k a g e") > -1;
  return 0 if index($tdata, $workbook_marker) > -1;
  return 1 if substr($data, 0x208, 1) eq "\xfe";
  return 1 if substr($data, 0x214, 1) eq "\x2f";
  return 1 if substr($data, 0x20B, 1) eq "\x13";

  return 0;
}

sub _is_office_doc {
  my ($data) = @_;

  return 0 if !defined $data || $data eq '';

  if (index($data, $marker1) == 0) {
    return 1;
  }

  return 0;
}

sub _is_zip_file {
  my ($name, $data) = @_;

  if (index($data, 'PK') == 0 || $name =~ /\.zip$/i) {
    return 1;
  }

  return 0;
}

sub _check_markers {
  my ($data) = @_;

  # Check for Office 2003 markers
  if (index($data, $marker1) == 0) {
    if (index($data, $marker2) > -1) {
      dbg('Marker 1 & 2 found');
      return 1;
    }
    if (index($data, $marker2a) > -1) {
      dbg('Marker 1 & 2a found');
      return 1;
    }
    return 0;
  }

  # Check for rtf markers
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

  # Check for Office 2007 markers
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

  my @binfiles = $zip->membersMatching('.*\.bin');

  foreach my $member (@binfiles) {
    my ($data, $status) = $member->contents();
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

  return if !defined $data || $data eq '';

  # http://download.microsoft.com/download/D/3/3/D334A189-E51B-47FF-B0E8-C0479AFB0E3C/[MS-OFFMACRO].pdf
  if ($data =~ /ContentType=["']application\/vnd\.ms-office\.vbaProject["']/i) {
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

# Version features
sub has_olemacro_redirect_uri { 1 }
sub has_olemacro_mhtml_uri { 1 }
sub has_olertfobject { 1 }

1;
