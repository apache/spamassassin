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

  extracttext_external    pdftohtml       /usr/bin/pdftohtml -i -stdout -noframes {}
  extracttext_external    pdftotext       /usr/bin/pdftotext -q -nopgbrk -enc UTF-8 {} -
  extracttext_use         pdftotext       .pdf application/pdf

  # http://docx2txt.sourceforge.net
  extracttext_external    docx2txt        /usr/bin/docx2txt {} -
  extracttext_use         docx2txt        .docx application/docx

  extracttext_external      antiword     /usr/bin/antiword -t -w 0 -m UTF-8.txt {} -
  extracttext_use           antiword     .doc application/(?:vnd\\.?)?ms-?word.*

  extracttext_external      unrtf        /usr/bin/unrtf --nopict {} -
  extracttext_use           unrtf        .doc .rtf application/rtf text/rtf

  extracttext_external      odt2txt      /usr/bin/odt2txt --encoding=UTF-8 {}
  extracttext_use           odt2txt      .odt .ott application/.*?opendocument.*text
  extracttext_use           odt2txt      .sdw .stw application/(?:x-)?soffice application/(?:x-)?starwriter

  extracttext_external      tesseract    /usr/bin/tesseract {} -
  extracttext_use           tesseract    .bmp .jpg .png image/jpeg

  add_header                all          ExtractText-Flags _EXTRACTTEXTFLAGS_
  header                    PDF_NO_TEXT  X-ExtractText-Flags =~ /pdftohtml_NoText/
  describe                  PDF_NO_TEXT  PDF without text

  header                    DOC_NO_TEXT  X-ExtractText-Flags =~ /(?:antiword|openxml|unrtf|odt2txt)_Notext/
  describe                  DOC_NO_TEXT  Document without text

  header                    EXTRACTTEXT  exists:X-ExtractText-Flags
  describe                  EXTRACTTEXT  Email processed by extracttext plugin
  score                     EXTRACTTEXT  0.001

endif

=head1 DESCRIPTION

This module uses external tools to extract text from message parts,
and then sets the text as the rendered part.

How to extract text is completely configurable, and based on
MIME part type and file name.

=head1 CONFIGURATION

In the configuration options, \ is used as an escape character. To include an
actual \ (in regexes for example), use \\.
All configuration lines in user_prefs files will be ignored.

=over 4

=item extracttext_maxparts (default: 10)

Configure the maximum mime parts number to analyze, a value of 0 means all mime parts
will be analyzed

=item extracttext_timeout (default: 5)

Configure the timeout in seconds of external tool checks

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

	extracttext_use  antiword  .doc application/(?:vnd\\.?)?ms-?word.*
	extracttext_use  openxml   .docx .dotx .dotm application/(?:vnd\\.?)openxml.*?word.*
	extracttext_use  openxml   .doc .dot application/(?:vnd\\.?)?ms-?word.*
	extracttext_use  unrtf     .doc .rtf application/rtf text/rtf

=over

=item extracttext_external

Defines an external tool. The tool must read a document on standard input or
from a file and write text to standard output.
The special keyword "{}" will be substituted at runtime with the temporary filename
to be scanned by the external tool.
If the tool doesn't write to stdout you can force it by appending a "-"
at the end of the configuration line.

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

X-ExtractText-Tools: pdftohtml openxml_antiword

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

=back

=head3 Rules

Example:

	header    PDF_NO_TEXT  X-ExtractText-Flags =~ /pdftohtml_Notext/
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

  $self->register_method_priority('post_message_parse',-1);
  $self->set_config($mailsa->{conf});
  return $self;
}

sub set_config {
  my($self, $conf) = @_;

  my @cmds;

  push(@cmds, {
    setting => 'extracttext_maxparts',
    default => 10,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });
  push(@cmds, {
    setting => 'extracttext_timeout',
    default => 5,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });
  $conf->{parser}->register_commands(\@cmds);
}

sub parse_config {
  my ($self, $opt) = @_;

  # ignore users's configuration lines
  return 0 if ($opt->{user_config});
  return 0 unless ($opt->{key} =~ /^extracttext_(.+)$/i);
  $self->inhibit_further_callbacks();

  my $key = lc($1);
  my @val = split(/\s+/, $opt->{value});
  if ($key eq 'use') {
    my $tool = lc(shift @val);
    return 0 unless ($tool && @val);
    foreach my $what (@val) {
      if ($what ne '') {
        my $where;
        if ($what =~ /.+\/.+/) {
          $where = 'type';
        } else {
          $where = 'name';
          $what = ".*\\$what"  if ($what =~ /^\.[a-zA-Z0-9]+$/);
        }
        push @{$self->{match}}, {where=>$where,what=>$what,tool=>$tool};
        dbg('extracttext: use: %s %s %s',$tool,$where,$what);
      }
    }
  } elsif ($key =~ /^external$/) {
    my $name = lc(shift @val);
    return 0 unless ($name && @val);
    if ($self->{tools}->{$name}) {
      warn "Tool exists: $name";
      return 0;
    }
    my $tool = {name=>$name,type=>$key};
    while (@val && $val[0] =~ /^\{(.*?)\}$/) {
      my $cmd = $1;
      my $val = 1;
      if ($cmd =~ /^(.*?):(.*)$/) {
        $cmd = $1;
        $val = $2;
      }
      shift @val;
    }
    return 0 unless (@val);
    $tool->{spec} = \@val;
    # External tools
    if ($tool->{type} eq 'external') {
      unless (-x $tool->{spec}->[0]) {
        warn "Missing tool: $tool->{name} ($tool->{spec}->[0])";
        return 0;
      }
      $tool->{timeout} = $opt->{conf}->{extracttext_timeout};
      dbg("extracttext: setting timeout to $tool->{timeout} for \"$name\"");
    } else {
      return 0;
    }
    $self->{tools}->{$name} = $tool;
    dbg('extracttext: %s: %s "%s"',$key,$name,join('","',@{$tool->{spec}}));
  } else {
    return 0;
  }
  $self->{maxparts} = $opt->{conf}->{extracttext_maxparts};
  return 1;
}

# Extract 'text' via running an external command.
sub _extract_external {
  my ($self,$object,$tool) = @_;
  my ($resp,$errno,$pipe_errno);
  my @cmd = @{$tool->{spec}};

  my ($path, $tmp_file, $pid);

  my $timeout = $tool->{timeout};

  Mail::SpamAssassin::PerMsgStatus::enter_helper_run_mode($self);

  my $timer = Mail::SpamAssassin::Timeout->new(
  { secs => $timeout, deadline => $self->{'master_deadline'} });
  my $err = $timer->run_and_catch(sub {
    local $SIG{PIPE} = sub { die "__brokenpipe__ignore__\n" };

    ($path, $tmp_file) = Mail::SpamAssassin::Util::secure_tmpfile();
    print $tmp_file ${$object->{data}};
    close($tmp_file);

    # if last parameter	is "-" push it to the end to write to stdout
    my $stdout = 0;
    if($cmd[-1] eq "-") {
      pop @cmd;
      $stdout = 1;
    }
    $path = untaint_file_path($path);
    my $i = 0;
    foreach my $cmd ( @cmd ) {
      # substitute "{}" with the temporary file name to pass to the external software
      if($cmd[$i] =~ /\{\}/) {
        $cmd[$i] = $path;
      }
      $cmd[$i] = untaint_file_path($cmd[$i]);
      $i++;
    }
    if($stdout eq 1) {
      push(@cmd, "-");
    }

    $pid = Mail::SpamAssassin::Util::helper_app_pipe_open(*EXTRACT,
    undef, 2, @cmd);
    $pid or die "$!\n";

    # read+split avoids a Perl I/O bug (Bug 5985)
    my($inbuf, $nread);
    $resp = '';

    while ($nread = read(EXTRACT, $inbuf, 8192)) { $resp .= $inbuf }
    defined $nread  or die "error reading from pipe: $!";

    $errno = 0;
    close EXTRACT or $errno = $!;

    if (proc_status_ok($?, $errno)) {
      dbg("extracttext: [%s] finished successfully", $pid);
    } elsif (proc_status_ok($?, $errno, 0, 1)) {  # sometimes it exits with 1
      dbg("extracttext: [%s] finished: %s", $pid, exit_status_str($?, $errno));
    } else {
      info("extracttext: [%s] error: %s", $pid, exit_status_str($?, $errno));
    }
    # Save return status for later
    $pipe_errno = $?;
  });

  if (defined(fileno(*EXTRACT))) {  # still open
    if ($pid) {
      if (kill('TERM', $pid)) {
        dbg("extracttext: killed stale helper [$pid]");
      } else {
        dbg("extracttext: killing helper application [$pid] failed: $!");
      }
    }
    $errno = 0;
    close EXTRACT or $errno = $!;
    proc_status_ok($?, $errno)
      or info("extracttext: [%s] error: %s", $pid, exit_status_str($?, $errno));
  }

  Mail::SpamAssassin::PerMsgStatus::leave_helper_run_mode($self);

  unlink($path);
  # If the output starts with the command that has been run it's
  # probably an error message
  my $basecmd = basename($cmd[0]);
  if ($pipe_errno && $resp =~ /Usage:\s+$basecmd\s+|No such file or directory/) {
    warn "wrong reply from $cmd[0], please verify command parameters (a '-' could be missing as last parameter).";
    return (0, undef);
  }
  if ($pipe_errno && !$resp) {
    warn "Error $pipe_errno without a proper response from $cmd[0]";
    return (0, undef);
  }
  return (1,$resp);
}

sub _extract_object {
  my ($self,$object,$tool) = @_;
  my ($ok,$extracted,$objects);
  if ($tool->{type} eq 'external') {
    ($ok,$extracted) = $self->_extract_external($object,$tool);
    if(defined $extracted) {
      # Remove not important html elements
      $extracted =~ s/(?=<!DOCTYPE)([\s\S]*?)>//g;
      $extracted =~ s/(?=<!--)([\s\S]*?)-->//g;
    }
  } else {
    warn "Bad tool type: $tool->{type}";
    return 0;
  }
  return 0 unless ($ok);

  $extracted = untaint_var($extracted);
  utf8::encode($extracted) if utf8::is_utf8($extracted);
  $extracted = '' if ($extracted =~ /^[\s\r\n]*$/s);
  if (not defined($extracted) or $extracted eq '') {
    dbg('extracttext: No text extracted');
  }
  return (1,$extracted);
}

sub _get_extension {
  my ($self,$object) = @_;
  my $fext;
  if (!$fext && $object->{name} && $object->{name} =~ /\.([^.\\\/]+)$/) {
    $fext = $1;
  }
  if (!$fext && $object->{file} && $object->{file} =~ /\.([^.\\\/]+)$/) {
    $fext = $1;
  }
  return $fext ? ($fext) : ();
}

sub _extract {
  my ($self,$coll,$part,$type,$name,$data,$tool) = @_;
  my $object = {
    data	=> $data,
    type	=> $type,
    name	=> $name
  };
  my @fexts;
  my @types;

  my @tools = ($tool->{name});
  my ($ok,$extracted) = $self->_extract_object($object,$tool);

  # when url+text, script never returns to this point from _extract_object above
  #
  return 0 unless ($ok);
  my $text = (defined($extracted)) ? $extracted : '';
  # debugging code
  # dbg("extracttext: text |$text| extracted");

  push @{$coll->{text}}, $text;
  push @types, $type;
  push @fexts, $self->_get_extension($object);
  if ($text eq '') {
    push @{$coll->{flags}},'NoText';
    dbg("extracttext: NoText");
    push @{$coll->{text}}, 'NoText';
  } else {
    if ($text =~ /<a href="(.*)"/) {
      push @{$coll->{flags}},'ActionURI';
      dbg("extracttext: ActionURI: $1");
      push @{$coll->{text}}, $text;
    }
    if ($text =~ /NoText/) {
      push @{$coll->{flags}},'NoText';
      dbg("extracttext: NoText");
      push @{$coll->{text}}, $text;
    }
    $coll->{chars} += length($text);
    $coll->{words} += scalar @{[split(/\W+/s,$text)]} - 1;
    # minimal heuristic to find out if output will be text/plain or text/html
    if($tool->{name} =~ /html/) {
      $type = "text/html";
    }
    dbg("extracttext: rendering text for type $type with $tool->{name}");
    $part->set_rendered($text, $type);
  }

  if (@types) {
    push @{$coll->{types}}, join(', ',@types) ;
  }
  if (@fexts) {
    push @{$coll->{extensions}}, join('_',@fexts) ;
  }
  push @{$coll->{tools}}, join('_',@tools) ;
  return 1;
}

#
# check attachment type and match with the right tool
#
sub _check_extract {
  my ($self,$coll,$checked,$part,$decoded,$data,$type,$name) = @_;
  return 0 unless (defined($type) || defined($name));
  foreach my $match (@{$self->{match}}) {
    next unless ($self->{tools}->{$match->{tool}});
    next if ($checked->{$match->{tool}});

    my ($rec, $err) = compile_regexp($match->{what}, 0);
    if (!$rec) {
      dbg("config: invalid regexp '$match->{what}': $err");
      return 1;
    }
    if ($match->{where} eq 'name') {
      next unless (defined($name) && $name =~ m/$rec/i);
    } elsif ($match->{where} eq 'type') {
      next unless (defined($type) && $type =~ m/$rec/i);
    } else {
      next;
    }
    $checked->{$match->{tool}} = 1;
    # dbg("extracttext: coll: $coll, part: $part, type: $type, name: $name, data: $data, tool: $self->{tools}->{$match->{tool}}");
    return 1 if ($self->_extract($coll,$part,$type,$name,$data,$self->{tools}->{$match->{tool}}));
  }
  return 0;
}

sub post_message_parse {
  my ($self, $pars) = @_;
  my $msg = $pars->{'message'};
  my $flags;
  my $nparts;

  return 0 unless ($msg);

  $self->{'master_deadline'} = $msg->{'master_deadline'};

  my %collect = (
    tools		=> [],
    types		=> [],
    extensions		=> [],
    flags		=> [],
    chars		=> 0,
    words		=> 0,
    text		=> [],
  );
  foreach my $part ($msg->find_parts(qr/./, 1)) {
    next unless ($part->is_leaf);
    $nparts++;
    if (defined ($self->{maxparts}) and ($self->{maxparts} > 0) and ($nparts > $self->{maxparts})) {
      dbg("extracttext: Skipping MIME parts exceeding the $self->{maxparts}th");
      last;
    }
    my ($rmt,$rtd) = $part->rendered;
    next if (defined($rtd));
    my %checked = ();
    my $dat = $part->decode();
    my $typ = $part->{type};
    my $nam = $part->{name};
    my $dec = 1;
    next if ($self->_check_extract(\%collect,\%checked,$part,\$dec,\$dat,$typ,$nam));
    next if ($self->_check_extract($msg,$part,\$dec,\$dat,'',''));
  }
  my %temp_tools = map { $_ => 1 } @{$collect{tools}};
  my @uniq_tools = keys %temp_tools;
  my $tools = join(' ',@uniq_tools) if (@{$collect{tools}});
  my %temp_types = map { $_ => 1 } @{$collect{types}};
  my @uniq_types = keys %temp_types;
  my $types = join(' ',@uniq_types) if (@{$collect{types}});
  my %temp_ext = map { $_ => 1 } @{$collect{extensions}};
  my @uniq_ext = keys %temp_ext;
  my $extensions = join(' ',@uniq_ext) if (@{$collect{extensions}});
  my %temp_flags = map { $_ => 1 } @{$collect{flags}};
  my @uniq_flags = keys %temp_flags;
  $flags = join(' ',@uniq_tools) if (@{$collect{tools}});
  $flags = $flags . "_" . join(' ',@uniq_flags) if (@{$collect{flags}});
  if(defined $tools) {
    $msg->put_metadata('X-ExtractText-Words',$collect{words});
    $msg->put_metadata('X-ExtractText-Chars',$collect{chars});
    $msg->put_metadata('X-ExtractText-Tools',$tools);
    $msg->put_metadata('X-ExtractText-Types',$types);
    $msg->put_metadata('X-ExtractText-Extensions',$extensions);
    $msg->put_metadata('X-ExtractText-Flags',$flags);
  }
  return 1;
}

sub parsed_metadata {
  my ($self,$pars) = @_;
  my $pms = $pars->{permsgstatus};
  return 0 unless ($pms);
  my $msg = $pms->get_message;
  return 0 unless ($msg);
  foreach my $tag (('Words','Chars','Tools','Types','Extensions','Flags')) {
    my $v = $msg->get_metadata("X-ExtractText-$tag");
    if(defined $v) {
      $pms->set_tag("ExtractText$tag", $v);
      dbg("extracttext: tag: $tag $v");
    }
  }
  return 1;
}

1;
