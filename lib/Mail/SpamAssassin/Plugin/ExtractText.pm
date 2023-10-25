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

# Authors: Jonas Eckerman, Dave Wreski, Giovanni Bechis

=head1 NAME

ExtractText - extracts text from documenmts.

=head1 SYNOPSIS

loadplugin Mail::SpamAssassin::Plugin::ExtractText

ifplugin Mail::SpamAssassin::Plugin::ExtractText

  extracttext_external  pdftotext  /usr/bin/pdftotext -nopgbrk -layout -enc UTF-8 {} -
  extracttext_use       pdftotext  .pdf application/pdf

  # http://docx2txt.sourceforge.net
  extracttext_external  docx2txt   /usr/bin/docx2txt {} -
  extracttext_use       docx2txt   .docx application/docx

  extracttext_external  antiword   /usr/bin/antiword -t -w 0 -m UTF-8.txt {}
  extracttext_use       antiword   .doc application/(?:vnd\.?)?ms-?word.*

  extracttext_external  unrtf      /usr/bin/unrtf --nopict {}
  extracttext_use       unrtf      .doc .rtf application/rtf text/rtf

  extracttext_external  odt2txt    /usr/bin/odt2txt --encoding=UTF-8 {}
  extracttext_use       odt2txt    .odt .ott application/.*?opendocument.*text
  extracttext_use       odt2txt    .sdw .stw application/(?:x-)?soffice application/(?:x-)?starwriter

  extracttext_external  tesseract  {OMP_THREAD_LIMIT=1} /usr/bin/tesseract -c page_separator= {} -
  extracttext_use       tesseract  .jpg .png .bmp .tif .tiff image/(?:jpeg|png|x-ms-bmp|tiff)

  # QR-code decoder
  extracttext_external  zbar       /usr/bin/zbarimg -q -D {}
  extracttext_use       zbar       .jpg .png .pdf image/(?:jpeg|png) application/pdf

  add_header   all          ExtractText-Flags _EXTRACTTEXTFLAGS_
  header       PDF_NO_TEXT  X-ExtractText-Flags =~ /\bpdftotext_NoText\b/
  describe     PDF_NO_TEXT  PDF without text
  score        PDF_NO_TEXT  0.001

  header       DOC_NO_TEXT  X-ExtractText-Flags =~ /\b(?:antiword|openxml|unrtf|odt2txt)_NoText\b/
  describe     DOC_NO_TEXT  Document without text
  score        DOC_NO_TEXT  0.001

  header       EXTRACTTEXT  exists:X-ExtractText-Flags
  describe     EXTRACTTEXT  Email processed by extracttext plugin
  score        EXTRACTTEXT  0.001

endif

=head1 DESCRIPTION

This module uses external tools to extract text from message parts,
and then sets the text as the rendered part. External tool must output
plain text, not HTML or other non-textual result.

How to extract text is completely configurable, and based on
MIME part type and file name.

=head1 CONFIGURATION

All configuration lines in user_prefs files will be ignored.

=over 4

=item extracttext_maxparts (default: 10)

Configure the maximum mime parts number to analyze, a value of 0 means all mime parts
will be analyzed

=item extracttext_timeout (default: 5 10)

Configure the timeout in seconds of external tool checks, per attachment.

Second argument speficies maximum total time for all checks.

=back

=head2 Tools

=over

=item extracttext_use

Specifies what tool to use for what message parts.

The general syntax is

extracttext_use  C<name>  C<specifiers>

=back

=over

=item name

the internal name of a tool.

=item specifiers

File extension and regular expressions for file names and MIME
types. The regular expressions are anchored to beginning and end.

=back

=head3 Examples

	extracttext_use  antiword  .doc application/(?:vnd\.?)?ms-?word.*
	extracttext_use  openxml   .docx .dotx .dotm application/(?:vnd\.?)openxml.*?word.*
	extracttext_use  openxml   .doc .dot application/(?:vnd\.?)?ms-?word.*
	extracttext_use  unrtf     .doc .rtf application/rtf text/rtf

=over

=item extracttext_external

Defines an external tool.  The tool must read a document on standard input
or from a file and write text to standard output.

The special keyword "{}" will be substituted at runtime with the temporary
filename to be scanned by the external tool.

Environment variables can be defined with "{KEY=VALUE}", these strings will
be removed from commandline.

It is required that commandline used outputs result directly to STDOUT.

The general syntax is

extracttext_external C<name> C<command> C<parameters>

=back

=over

=item name

The internal name of this tool.

=item command

The full path to the external command to run.

=item parameters

Parameters for the external command. The temporary file name containing
the document will be automatically added as last parameter.

=back

=head3 Examples

	extracttext_external  antiword  /usr/bin/antiword -t -w 0 -m UTF-8.txt {} -
	extracttext_external  unrtf     /usr/bin/unrtf --nopict {}
	extracttext_external  odt2txt   /usr/bin/odt2txt --encoding=UTF-8 {}

=head2 Metadata

The plugin adds some pseudo headers to the message. These headers are seen by
the bayes system, and can be used in normal SpamAssassin rules.

The headers are also available as template tags as noted below.

=head3 Example

The fictional example headers below are based on a message containing this:

=over

=item 1
A perfectly normal PDF.

=item 2
An OpenXML document with a word document inside.
Neither Office document contains text.

=back

=head3 Headers

=over

=item X-ExtractText-Chars

Tag: _EXTRACTTEXTCHARS_

Contains a count of characters that were extracted.

X-ExtractText-Chars: 10970

=item X-ExtractText-Words

Tag: _EXTRACTTEXTWORDS_

Contains a count of "words" that were extracted.

X-ExtractText-Chars: 1599

=item X-ExtractText-Tools

Tag: _EXTRACTTEXTTOOLS_

Contains chains of tools used for extraction.

X-ExtractText-Tools: pdftotext openxml_antiword

=item X-ExtractText-Types

Tag: _EXTRACTTEXTTYPES_

Contains chains of MIME types for parts found during extraction.

X-ExtractText-Types: application/pdf; application/vnd.openxmlformats-officedocument.wordprocessingml.document, application/ms-word

=item X-ExtractText-Extensions

Tag: _EXTRACTTEXTEXTENSIONS_

Contains chains of canonicalized file extensions for parts
found during extraction.

X-ExtractText-Extensions: pdf docx

=item X-ExtractText-Flags

Tag: _EXTRACTTEXTFLAGS_

Contains notes from the plugin.

X-ExtractText-Flags: openxml_NoText

=item X-ExtractText-Uris

Tag: _EXTRACTTEXTURIS_

Contains uris extracted from the plugin.

X-ExtractText-Uris: https://spamassassin.apache.org

=back

=head3 Rules

Example:

	header    PDF_NO_TEXT  X-ExtractText-Flags =~ /\bpdftotext_Notext\b/
	describe  PDF_NO_TEXT  PDF without text

=cut

package Mail::SpamAssassin::Plugin::ExtractText;

use strict;
use warnings;
use re 'taint';

my $VERSION = 0.001;

use File::Basename;

use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Util qw (compile_regexp untaint_var untaint_file_path
  proc_status_ok exit_status_str);

our @ISA = qw(Mail::SpamAssassin::Plugin);

sub new {
  my ($class, $mailsa) = @_;

  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsa);
  bless ($self, $class);

  $self->{match} = [];
  $self->{tools} = {};
  $self->{magic} = 0;

  $self->register_method_priority('post_message_parse', -1);
  $self->set_config($mailsa->{conf});
  return $self;
}

sub set_config {
  my ($self, $conf) = @_;
  my @cmds;

  push(@cmds, {
    setting => 'extracttext_maxparts',
    is_admin => 1,
    default => 10,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });

  push(@cmds, {
    setting => 'extracttext_timeout',
    is_admin => 1,
    default => 5,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      unless (defined $value && $value !~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      local ($1,$2);
      unless ($value =~ /^(\d+)(?:\s+(\d+))?$/) {
        return $Mail::SpamAssassin::Conf::INVALID_VALUE;
      }
      $self->{extracttext_timeout} = $1;
      $self->{extracttext_timeout_total} = $2;
    }
  });

  $conf->{parser}->register_commands(\@cmds);
}

sub parse_config {
  my ($self, $opts) = @_;

  # Ignore users's configuration lines
  return 0 if $opts->{user_config};

  if ($opts->{key} eq 'extracttext_use') {
    $self->inhibit_further_callbacks();
    # Temporary kludge to notify users. Double backslashes have zero benefit for this plugin config.
    if ($opts->{value} =~ s/\\\\/\\/g) {
      warn "extracttext: DOUBLE BACKSLASHES DEPRECATED, change config to single backslashes, autoconverted for backward compatibility: $opts->{key} $opts->{value}\n";
    }
    if ($opts->{value} =~ /(?:to|2)html\b/) {
      warn "extracttext: HTML tools are not supported, plain text output is required. Please remove: $opts->{key} $opts->{value}\n";
      return 1;
    }
    my @vals = split(/\s+/, $opts->{value});
    my $tool = lc(shift @vals);
    return 0 unless @vals;
    foreach my $what (@vals) {
      my $where;
      if (index($what, '/') >= 0) {
        $where = 'type';
      } else {
        $where = 'name';
        if ($what =~ /^\.[a-zA-Z0-9]+$/) {
          $what = ".*\\$what";
        }
      }
      my ($rec, $err) = compile_regexp('^(?i)'.$what.'$', 0);
      if (!$rec) {
        warn("invalid regexp '$what': $err\n");
        return 0;
      }
      push @{$self->{match}}, {where=>$where, what=>$rec, tool=>$tool};
      dbg('extracttext: use: %s %s %s', $tool, $where, $what);
    }
    return 1;
  }
  
  if ($opts->{key} eq 'extracttext_external') {
    $self->inhibit_further_callbacks();
    # Temporary kludge to notify users. Double backslashes have zero benefit for this plugin config.
    if ($opts->{value} =~ s/\\\\/\\/g) {
      warn "extracttext: DOUBLE BACKSLASHES DEPRECATED, change config to single backslashes, autoconverted for backward compatibility: $opts->{key} $opts->{value}\n";
    }
    if ($opts->{value} =~ /(?:to|2)html\b/) {
      warn "extracttext: HTML tools are not supported, plain text output is required. Please remove: $opts->{key} $opts->{value}\n";
      return 1;
    }
    my %env;
    while ($opts->{value} =~ s/\{(.+?)\}/ /g) {
      my ($k,$v) = split(/=/, $1, 2);
      $env{$k} = defined $v ? $v : '';
    }
    my @vals = split(/\s+/, $opts->{value});
    my $name = lc(shift @vals);
    return 0 unless @vals > 1;
    if ($self->{tools}->{$name}) {
      warn "extracttext: duplicate tool defined: $name\n";
      return 0;
    }
    #unless (-x $vals[0]) {
    #  warn "extracttext: missing tool: $name ($vals[0])\n";
    #  return 0;
    #}
    $self->{tools}->{$name} = {
      'name' => $name,
      'type' => 'external',
      'env' => \%env,
      'cmd' => \@vals,
    };
    dbg('extracttext: external: %s "%s"', $name, join('","', @vals));
    return 1;
  }

  return 0;
}

# Extract 'text' via running an external command.
sub _extract_external {
  my ($self, $object, $tool) = @_;

  my ($errno, $pipe_errno, $tmp_file, $err_file, $pid);
  my $resp = '';
  my @cmd = @{$tool->{cmd}};

  Mail::SpamAssassin::PerMsgStatus::enter_helper_run_mode($self);

  # Set environment variables
  foreach (keys %{$tool->{env}}) {
    $ENV{$_} = $tool->{env}{$_};
  }

  my $timer = Mail::SpamAssassin::Timeout->new(
    { secs => $self->{main}->{conf}->{extracttext_timeout},
      deadline => $self->{'master_deadline'} });

  my $err = $timer->run_and_catch(sub {
    local $SIG{PIPE} = sub { die "__brokenpipe__ignore__\n" };

    ($tmp_file, my $tmp_fh) = Mail::SpamAssassin::Util::secure_tmpfile();
    $tmp_file  or die "failed to create a temporary file";
    print $tmp_fh ${$object->{data}};
    close($tmp_fh);

    ($err_file, my $err_fh) = Mail::SpamAssassin::Util::secure_tmpfile();
    $err_file  or die "failed to create a temporary file";
    close($err_fh);
    $err_file = untaint_file_path($err_file);

    foreach (@cmd) {
      # substitute "{}" with the temporary file name to pass to the external software
      s/\{\}/$tmp_file/;
      $_ = untaint_var($_);
    }

    $pid = Mail::SpamAssassin::Util::helper_app_pipe_open(*EXTRACT, undef, ">$err_file", @cmd);
    $pid or die "$!\n";

    # read+split avoids a Perl I/O bug (Bug 5985)
    my($inbuf, $nread);

    while ($nread = read(EXTRACT, $inbuf, 8192)) { $resp .= $inbuf }
    defined $nread  or die "error reading from pipe: $!";

    $errno = 0;
    close EXTRACT or $errno = $!;

    if (proc_status_ok($?, $errno)) {
      dbg("extracttext: [%s] (%s) finished successfully", $pid, $cmd[0]);
    } elsif (proc_status_ok($?, $errno, 0, 1, 4)) {  # sometimes it exits with error 1 or 4
      dbg("extracttext: [%s] (%s) finished: %s", $pid, $cmd[0], exit_status_str($?, $errno));
    } else {
      info("extracttext: [%s] (%s) error: %s", $pid, $cmd[0], exit_status_str($?, $errno));
    }
    # Save return status for later
    $pipe_errno = $?;
  });

  if (defined(fileno(*EXTRACT))) {  # still open
    if ($pid) {
      if (kill('TERM', $pid)) {
        dbg("extracttext: killed stale helper [$pid] ($cmd[0])");
      } else {
        dbg("extracttext: killing helper application [$pid] ($cmd[0]) failed: $!");
      }
    }
    $errno = 0;
    close EXTRACT or $errno = $!;
    proc_status_ok($?, $errno)
      or info("extracttext: [%s] (%s) error: %s", $pid, $cmd[0], exit_status_str($?, $errno));
  }

  Mail::SpamAssassin::PerMsgStatus::leave_helper_run_mode($self);
  unlink($tmp_file);
  # Read first line from STDERR
  my $err_resp = -s $err_file ?
    do { open(ERRF, $err_file); $_ = <ERRF>; close(ERRF); chomp; $_; } : '';
  unlink($err_file);

  if ($err_resp ne '') {
    dbg("extracttext: [$pid] ($cmd[0]) stderr output: $err_resp");
  }

  # If the output starts with the command that has been run it's
  # probably an error message
  if ($pipe_errno) {
    if ($err_resp =~ /\b(?:Usage:|No such file or directory)/) {
      warn "extracttext: error from $cmd[0], please verify configuration: $err_resp\n";
    }
    elsif ($err_resp =~ /^Syntax (?:Warning|Error): (?:May not be a PDF file|Couldn't find trailer dictionary)/) {
      # Ignore pdftotext
    }
    elsif ($err_resp =~ /^Error in (?:findFileFormatStream|fopenReadStream): (?:truncated file|file not found)/) {
      # Ignore tesseract
    }
    elsif ($err_resp =~ /^libpng error:/) {
      # Ignore tesseract
    }
    elsif ($err_resp =~ /^Corrupt JPEG data:/) {
      # Ignore tesseract
    }
    elsif ($err_resp =~ /^\S+ is not a Word Document/) {
      # Ignore antiword
    } elsif((($pipe_errno/256) eq 4) and ($cmd[0] =~ /zbarimg/)) {
      # Ignore zbarimg
    }
    elsif (!$resp) {
      warn "extracttext: error (".($pipe_errno/256).") from $cmd[0]: $err_resp\n";
    }
    return (0, $resp);
  }
  return (1, $resp);
}

sub _extract_object {
  my ($self, $object, $tool) = @_;
  my ($ok, $text);

  if ($tool->{type} eq 'external') {
    ($ok, $text) = $self->_extract_external($object, $tool);
  } else {
    warn "extracttext: bad tool type: $tool->{type}\n";
    return 0;
  }

  return 0 unless $ok;

  if ($text =~ /^[\s\r\n]*$/s) {
    $text = '';
  } else {
    # Remove not important html elements
    #$text =~ s/(?=<!DOCTYPE)([\s\S]*?)>//g;
    #$text =~ s/(?=<!--)([\s\S]*?)-->//g;
  }

  if ($text eq '') {
    dbg('extracttext: No text extracted');
  }

  $text = untaint_var($text);
  utf8::encode($text) if utf8::is_utf8($text);

  return (1, $text);
}

sub _get_extension {
  my ($self, $object) = @_;
  my $fext;
  if ($object->{name} && $object->{name} =~ /\.([^.\\\/]+)$/) {
    $fext = $1;
  }
  elsif ($object->{file} && $object->{file} =~ /\.([^.\\\/]+)$/) {
    $fext = $1;
  }
  return $fext ? ($fext) : ();
}

sub _extract {
  my ($self, $coll, $part, $type, $name, $data, $tool) = @_;
  my $object = {
    'data' => $data,
    'type' => $type,
    'name' => $name
  };
  my @fexts;
  my @types;

  my @tools = ($tool->{name});
  my ($ok, $text) = $self->_extract_object($object,$tool);

  # when url+text, script never returns to this point from _extract_object above
  #
  return 0 unless $ok;
  if ($text ne '' && would_log('dbg','extracttext') > 1) {
    dbg("extracttext: text extracted:\n$text");
  }

  push @{$coll->{text}}, $text;
  push @types, $type;
  push @fexts, $self->_get_extension($object);
  if ($text eq '') {
    push @{$coll->{flags}}, 'NoText';
    push @{$coll->{text}}, 'NoText';
  } else {
    if ($text =~ /<a(?:\s+[^>]+)?\s+href="([^">]*)"/) {
      push @{$coll->{flags}}, 'ActionURI';
      dbg("extracttext: ActionURI: $1");
      push @{$coll->{text}}, $text;
      push @{$coll->{uris}}, $2;
    } elsif($text =~ /QR-Code\:([^\s]*)/) {
      # zbarimg(1) prefixes the url with "QR-Code:" string
      my $qrurl = $1;
      push @{$coll->{flags}},'QR-Code';
      dbg("extracttext: QR-Code: $qrurl");
      push @{$coll->{text}}, $text;
      push @{$coll->{uris}}, $qrurl;
    }
    if ($text =~ /NoText/) {
      push @{$coll->{flags}},'NoText';
      dbg("extracttext: NoText");
      push @{$coll->{text}}, $text;
    }
    $coll->{chars} += length($text);

    # the following is safe (regarding clobbering the @_) since perl v5.11.0
    $coll->{words} += split(/\W+/s,$text) - 1;
    # $coll->{words} += scalar @{[split(/\W+/s,$text)]} - 1;  # old perl hack

    dbg("extracttext: rendering text for type $type with $tool->{name}");
    $part->set_rendered($text);
  }

  if (@types) {
    push @{$coll->{types}}, join(', ', @types);
  }
  if (@fexts) {
    push @{$coll->{extensions}}, join('_', @fexts);
  }
  push @{$coll->{tools}}, join('_', @tools);
  return 1;
}

#
# check attachment type and match with the right tool
#
sub _check_extract {
  my ($self, $coll, $checked, $part, $decoded, $data, $type, $name) = @_;
  my $ret = 0;
  return 0 unless (defined $type || defined $name);
  foreach my $match (@{$self->{match}}) {
    next unless $self->{tools}->{$match->{tool}};
    next if $checked->{$match->{tool}};

    if ($match->{where} eq 'name') {
      next unless (defined $name && $name =~ $match->{what});
    } elsif ($match->{where} eq 'type') {
      next unless (defined $type && $type =~ $match->{what});
    } else {
      next;
    }
    $checked->{$match->{tool}} = 1;
    # dbg("extracttext: coll: $coll, part: $part, type: $type, name: $name, data: $data, tool: $self->{tools}->{$match->{tool}}");
    if($self->_extract($coll,$part,$type,$name,$data,$self->{tools}->{$match->{tool}})) {
      $ret = 1;
    }
  }
  return $ret;
}

sub post_message_parse {
  my ($self, $opts) = @_;

  my $timer = $self->{main}->time_method("extracttext");

  my $msg = $opts->{'message'};
  $self->{'master_deadline'} = $msg->{'master_deadline'};
  my $starttime = time;

  my %collect = (
    'tools'		=> [],
    'types'		=> [],
    'extensions'	=> [],
    'flags'		=> [],
    'chars'		=> 0,
    'words'		=> 0,
    'text'		=> [],
    'uris'		=> [],
  );

  my $conf = $self->{main}->{conf};
  my $maxparts = $conf->{extracttext_maxparts};
  my $ttimeout = $conf->{extracttext_timeout_total} ||
    $conf->{extracttext_timeout} > 10 ? $conf->{extracttext_timeout} : 10;
  my $nparts = 0;
  foreach my $part ($msg->find_parts(qr/./, 1)) {
    next unless $part->is_leaf;
    if ($maxparts > 0 && ++$nparts > $maxparts) {
      dbg("extracttext: Skipping MIME parts exceeding the ${maxparts}th");
      last;
    }
    if (time - $starttime >= $ttimeout) {
      dbg("extracttext: Skipping MIME parts, total execution timeout exceeded");
      last;
    }
    my (undef,$rtd) = $part->rendered;
    next if defined $rtd;
    my %checked = ();
    my $dat = $part->decode();
    my $typ = $part->{type};
    my $nam = $part->{name};
    my $dec = 1;
    next if $self->_check_extract(\%collect,\%checked,$part,\$dec,\$dat,$typ,$nam);
  }

  return 1 unless @{$collect{tools}};

  my @uniq_tools = do { my %seen; grep { !$seen{$_}++ } @{$collect{tools}} };
  my @uniq_types = do { my %seen; grep { !$seen{$_}++ } @{$collect{types}} };
  my @uniq_ext   = do { my %seen; grep { !$seen{$_}++ } @{$collect{extensions}} };
  my @uniq_flags = do { my %seen; grep { !$seen{$_}++ } @{$collect{flags}} };
  my @uniq_uris = do { my %seen; grep { !$seen{$_}++ } @{$collect{uris}} };

  $msg->put_metadata('X-ExtractText-Words', $collect{words});
  $msg->put_metadata('X-ExtractText-Chars', $collect{chars});
  $msg->put_metadata('X-ExtractText-Tools', join(' ', @uniq_tools));
  $msg->put_metadata('X-ExtractText-Types', join(' ', @uniq_types));
  $msg->put_metadata('X-ExtractText-Extensions', join(' ', @uniq_ext));
  $msg->put_metadata('X-ExtractText-Flags', join(' ', @uniq_flags));
  $msg->put_metadata('X-ExtractText-Uris', join(' ', @uniq_uris));

  return 1;
}

sub parsed_metadata {
  my ($self, $opts) = @_;
  my $pms = $opts->{permsgstatus};
  my $msg = $pms->get_message();
  foreach my $tag (('Words','Chars','Tools','Types','Extensions','Flags','Uris')) {
    my $v = $msg->get_metadata("X-ExtractText-$tag");
    if (defined $v) {
      $pms->set_tag("ExtractText$tag", $v);
      dbg("extracttext: tag: $tag $v");
    }
  }
  return 1;
}

1;
