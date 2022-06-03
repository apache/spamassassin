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

package Mail::SpamAssassin::Plugin::FreeMail;
use strict;
use warnings;
use re 'taint';

my $VERSION = 4.000;

=head1 NAME

FreeMail - check message headers/body for freemail-domains

=head1 SYNOPSIS

If for example From-address is freemail, and Reply-To or address found in mail body is
different freemail address, return success.  Good sign of Nigerian scams
etc.  Test idea from Marc Perkel.

Also separate functions to check various portions of message for freemails.

=head1 CONFIGURATION

freemail_domains domain ...

   List of domains to be used in checks.

   Regexp is not supported, but following wildcards work:

   ? for single character (does not match a dot)
   * for multiple characters (does not match a dot)

   For example:
   freemail_domains hotmail.com hotmail.co.?? yahoo.* yahoo.*.*

freemail_welcomelist email/domain ...

   Previously freemail_whitelist which will work interchangeably until 4.1.

   Emails or domains listed here are ignored (pretend they aren't
   freemail). No wildcards!

freemail_import_welcomelist_auth 1/0

   Entries in welcomelist_auth will also be used to welcomelist emails
   or domains from being freemail.  Default is 0.

freemail_import_def_welcomelist_auth 1/0

   Entries in def_welcomelist_auth will also be used to welcomelist emails
   or domains from being freemail.  Default is 0.

header FREEMAIL_REPLYTO eval:check_freemail_replyto(['option'])

   Checks/compares freemail addresses found from headers and body.

   Possible options:

   replyto	From: or body address is different than Reply-To
		(this is the default)
   reply	as above, but if no Reply-To header is found,
		compares From: and body

header FREEMAIL_FROM eval:check_freemail_from(['regex'])

   Checks all possible "from" headers to see if sender is freemail.
   Uses SA all_from_addrs() function (includes 'Resent-From', 'From',
   'EnvelopeFrom' etc).

   Add optional regex to match the found email address(es). For example,
   to see if user ends in digit: check_freemail_from('\d@')

   If you use multiple check_freemail_from rules with regexes, remember
   that they might hit different emails from different heades. To match
   a certain header only, use check_freemail_header.

header FREEMAIL_HDRX eval:check_freemail_header('header' [, 'regex'])

   Searches defined header for freemail address. Optional regex to match
   the found address (like in check_freemail_from).

header FREEMAIL_BODY eval:check_freemail_body(['regex'])

   Searches body for freemail address. With optional regex to match.

=cut

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::PerMsgStatus;
use Mail::SpamAssassin::Util qw(compile_regexp);

our @ISA = qw(Mail::SpamAssassin::Plugin);

# default email welcomelist
our $email_welcomelist = qr/
  ^(?:
      abuse|support|sales|info|helpdesk|contact|kontakt
    | (?:post|host|domain)master
    | undisclosed.*			# yahoo.com etc(?)
    | request-[a-f0-9]{16}		# live.com
    | bounced?-				# yahoo.com etc
    | [a-f0-9]{8}(?:\.[a-f0-9]{8}|-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}) # gmail msgids?
    | .+=.+=.+				# gmail forward
  )\@
/xi;

# skip replyto check when envelope sender is
# allow <> for now
# no re "strict";  # since perl 5.21.8: Ranges of ASCII printables...
our $skip_replyto_envfrom = qr/
  (?:
      ^(?:post|host|domain)master
    | ^double-bounce
    | ^(?:sentto|owner|return|(?:gr)?bounced?)-.+
    | -(?:request|bounces?|admin|owner)
    | \b(?:do[._-t]?)?no[._-t]?repl(?:y|ies)
    | .+=.+
  )\@
/xi;

sub dbg { my $msg = shift; Mail::SpamAssassin::Plugin::dbg("FreeMail: $msg", @_); }

sub new {
    my ($class, $mailsa) = @_;

    $class = ref($class) || $class;
    my $self = $class->SUPER::new($mailsa);
    bless ($self, $class);

    $self->{freemail_available} = 1;
    $self->set_config($mailsa->{conf});
    $self->register_eval_rule("check_freemail_replyto", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
    $self->register_eval_rule("check_freemail_from", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
    $self->register_eval_rule("check_freemail_header", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);
    $self->register_eval_rule("check_freemail_body", $Mail::SpamAssassin::Conf::TYPE_HEAD_EVALS);

    return $self;
}

sub _init_email_regex {
    my ($self) = @_;

    dbg("initializing email regex");

    # Some regexp tips courtesy of http://www.regular-expressions.info/email.html
    # full email regex v0.02
    $self->{email_regex} = qr/
      (?=.{0,64}\@)				# limit userpart to 64 chars (and speed up searching?)
      (?<![a-z0-9!#\$%&'*+\/=?^_`{|}~-])	# start boundary
      (						# capture email
      [a-z0-9!#\$%&'*+\/=?^_`{|}~-]+		# no dot in beginning
      (?:\.[a-z0-9!#\$%&'*+\/=?^_`{|}~-]+)*	# no consecutive dots, no ending dot
      \@
      (?:[a-z0-9](?:[a-z0-9-]{0,59}[a-z0-9])?\.){1,4} # max 4x61 char parts (should be enough?)
      $self->{main}->{registryboundaries}->{valid_tlds_re}	# ends with valid tld
      )
    /xi;
}

sub set_config {
    my ($self, $conf) = @_;
    my @cmds;
    push(@cmds, {
        setting => 'freemail_max_body_emails',
        default => 5,
        type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
        }
    );
    push(@cmds, {
        setting => 'freemail_max_body_freemails',
        default => 3,
        type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
        }
    );
    push(@cmds, {
        setting => 'freemail_skip_when_over_max',
        default => 1,
        type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
        }
    );
    push(@cmds, {
        setting => 'freemail_skip_bulk_envfrom',
        default => 1,
        type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
        }
    );
    push(@cmds, {
        setting => 'freemail_add_describe_email',
        default => 1,
        type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
        }
    );
    push(@cmds, {
        setting => 'freemail_import_welcomelist_auth',
        aliases => ['freemail_import_whitelist_auth'], # removed in 4.1
        default => 0,
        type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
        }
    );
    push(@cmds, {
        setting => 'freemail_import_def_welcomelist_auth',
        aliases => ['freemail_import_def_whitelist_auth'], # removed in 4.1
        default => 0,
        type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
        }
    );
    $conf->{parser}->register_commands(\@cmds);
}

sub parse_config {
    my ($self, $opts) = @_;

    if ($opts->{key} eq "freemail_domains") {
        foreach my $temp (split(/\s+/, $opts->{value})) {
            if ($temp !~ tr/a-zA-Z0-9.*?-//c) {
                my $value = lc($temp);
                if ($value =~ tr/*?//) { # separate wildcard list
                    $self->{freemail_temp_wc}{$value} = 1;
                }
                else {
                    $self->{freemail_domains}{$value} = 1;
                }
            }
            else {
                warn("freemail: invalid freemail_domains: $temp\n");
            }
        }
        $self->inhibit_further_callbacks();
        return 1;
    }

    if ($opts->{key} eq "freemail_welcomelist" || $opts->{key} eq "freemail_whitelist") {
        foreach my $temp (split(/\s+/, $opts->{value})) {
            my $value = lc($temp);
            if ($value =~ /\w[.@]\w/) {
                $self->{freemail_welcomelist}{$value} = 1;
            }
            else {
                warn("freemail: invalid freemail_welcomelist: $temp\n");
            }
        }
        $self->inhibit_further_callbacks();
        return 1;
    }

    return 0;
}

sub finish_parsing_end {
    my ($self, $opts) = @_;

    my $wcount = 0;
    if (defined $self->{freemail_temp_wc}) {
        my @domains;
        foreach my $value (keys %{$self->{freemail_temp_wc}}) {
            $value =~ s/\./\\./g;
            $value =~ s/\?/./g;
            $value =~ s/\*/[^.]*/g;
            push(@domains, $value);
        }
        my $doms = join('|', @domains);
        $self->{freemail_domains_re} = qr/\@(?:${doms})$/;
        $wcount = scalar @domains;
        undef $self->{freemail_temp_wc};
        delete $self->{freemail_temp_wc};
    }

    my $count = scalar keys %{$self->{freemail_domains}};
    if ($count + $wcount) {
        dbg("loaded freemail_domains entries: $count normal, $wcount wildcard");
    }
    else {
        dbg("no freemail_domains entries defined, disabling plugin");
        $self->{freemail_available} = 0;
    }

    # valid_tlds_re will be available at finish_parsing_end, compile it now,
    # we only need to do it once and before possible forking
    if ($self->{freemail_available} && !$self->{email_regex}) {
        $self->_init_email_regex();
    }

    return 0;
}

sub _is_freemail {
    my ($self, $email, $pms) = @_;

    return 0 if $email eq '';

    if (defined $self->{freemail_welcomelist}{$email}) {
        dbg("welcomelisted email: $email");
        return 0;
    }

    my $domain = $email;
    $domain =~ s/.*\@//;

    if (defined $self->{freemail_welcomelist}{$domain}) {
        dbg("welcomelisted domain: $domain");
        return 0;
    }

    if ($email =~ $email_welcomelist) {
        dbg("welcomelisted email, default: $email");
        return 0;
    }

    foreach my $list ('welcomelist_auth','def_welcomelist_auth') {
        if ($pms->{conf}->{"freemail_import_$list"}) {
            foreach my $regexp (values %{$pms->{conf}->{$list}}) {
                if ($email =~ /$regexp/o) {
                    dbg("welcomelisted email, $list: $email");
                    return 0;
                }
            }
        }
    }
 
    if (defined $self->{freemail_domains}{$domain}
        or ( defined $self->{freemail_domains_re}
             and $email =~ $self->{freemail_domains_re} )) {
        return 1;
    }

    return 0;
}

sub _parse_body {
    my ($self, $pms) = @_;

    # Parse body
    if (not defined $pms->{freemail_cache}{body}) {
        %{$pms->{freemail_cache}{body}} = ();
        my %seen;
        my @body_emails;
        # get all <a href="mailto:", since they don't show up on stripped_body
        my $parsed = $pms->get_uri_detail_list();
        while (my($uri, $info) = each %{$parsed}) {
            if (defined $info->{types}->{a} and not defined $info->{types}->{parsed}) {
                if ($uri =~ /^(?:(?i)mailto):$self->{email_regex}/o) {
                    my $email = lc($1);
                    push(@body_emails, $email) unless defined $seen{$email};
                    $seen{$email} = 1;
                    last if scalar @body_emails >= 20; # sanity
                }
            }
        }
        # scan stripped normalized body
        # have to do this way since get_uri_detail_list doesn't know what mails are inside <>
        my $body = $pms->get_decoded_stripped_body_text_array();
        BODY: foreach (@$body) {
            # strip urls with possible emails inside
            s{<?https?://\S{0,255}(?:\@|%40)\S{0,255}}{ }gi;
            # strip emails contained in <>, not mailto:
            # also strip ones followed by quote-like "wrote:" (but not fax: and tel: etc)
            s{<?(?<!mailto:)$self->{email_regex}(?:>|\s{1,10}(?!(?:fa(?:x|csi)|tel|phone|e?-?mail))[a-z]{2,11}:)}{ }gi;
            while (/$self->{email_regex}/g) {
                my $email = lc($1);
                utf8::encode($email) if utf8::is_utf8($email); # chars to UTF-8
                push(@body_emails, $email) unless $seen{$email};
                $seen{$email} = 1;
                last BODY if @body_emails >= 40; # sanity
            }
        }
        my $count_all = 0;
        my $count_fm = 0;
        foreach my $email (@body_emails) {  # as UTF-8 octets
            if (++$count_all == $pms->{main}->{conf}->{freemail_max_body_emails}) {
                if ($pms->{main}->{conf}->{freemail_skip_when_over_max}) {
                    $pms->{freemail_skip_body} = 1;
                    dbg("too many unique emails found from body");
                    return 0;
                }
            }
            next unless $self->_is_freemail($email, $pms);
            if (++$count_fm == $pms->{main}->{conf}->{freemail_max_body_freemails}) {
                if ($pms->{main}->{conf}->{freemail_skip_when_over_max}) {
                    $pms->{freemail_skip_body} = 1;
                    dbg("too many unique freemails found from body");	
                    return 0;
                }
            }
            $pms->{freemail_cache}{body}{$email} = 1;
        }
        dbg("all body freemails: ".join(', ', keys %{$pms->{freemail_cache}{body}}))
            if scalar keys %{$pms->{freemail_cache}{body}};
    }

    if (defined $pms->{freemail_skip_body}) {
        dbg("[cached] body email limit exceeded, skipping");
        return 0;
    }

    return 1;
}

sub _test_log {
    my ($self, $pms, $email, $rulename) = @_;

    if ($pms->{conf}->{freemail_add_describe_email}) {
        $email =~ s/\@/(at)/g;
        $pms->test_log($email, $rulename);
    }
}

sub check_freemail_header {
    my ($self, $pms, $header, $regex) = @_;

    return 0 unless $self->{freemail_available};

    my $rulename = $pms->get_current_eval_rule_name();
    dbg("RULE ($rulename) check_freemail_header".(defined $regex ? " regex:$regex" : ""));

    unless (defined $header) {
        warn("freemail: check_freemail_header needs argument\n");
        return 0;
    }

    my $re;
    if (defined $regex) {
        my ($rec, $err) = compile_regexp($regex, 0);
        if (!$rec) {
            warn "freemail: invalid regexp for $rulename '$regex': $err\n";
            return 0;
        }
        $re = $rec;
    }

    my @emails = map (lc, $pms->get("$header:addr"));

    if (!scalar (@emails)) {
         dbg("header $header not found from mail");
         return 0;
    }
    dbg("addresses from header $header: ".join(', ', @emails));

    foreach my $email (@emails) {    
        if ($self->_is_freemail($email, $pms)) {
            if (defined $re) {
                next unless $email =~ /$re/o;
                dbg("HIT! $email is freemail and matches regex");
            }
            else {
                dbg("HIT! $email is freemail");
            }
            $self->_test_log($pms, $email, $rulename);
            return 1;
         }
    }

    return 0;
}

sub check_freemail_body {
    my ($self, $pms, $regex) = @_;

    return 0 unless $self->{freemail_available};

    my $rulename = $pms->get_current_eval_rule_name();
    dbg("RULE ($rulename) check_freemail_body".(defined $regex ? " regex:$regex" : ""));

    return 0 unless $self->_parse_body($pms);

    my $re;
    if (defined $regex) {
        my ($rec, $err) = compile_regexp($regex, 0);
        if (!$rec) {
            warn "freemail: invalid regexp for $rulename '$regex': $err\n";
            return 0;
        }
        $re = $rec;
    }

    if (defined $re) {
        foreach my $email (keys %{$pms->{freemail_cache}{body}}) {
            if ($email =~ /$re/o) {
                dbg("HIT! email from body is freemail and matches regex: $email");
                $self->_test_log($pms, $email, $rulename);
                return 1;
            }
        }
    }
    elsif (scalar keys %{$pms->{freemail_cache}{body}}) {
        my $emails = join(', ', keys %{$pms->{freemail_cache}{body}});
        dbg("HIT! body has freemails: $emails");
        $self->_test_log($pms, $emails, $rulename);
        return 1;
    }

    return 0;
}

sub check_freemail_from {
    my ($self, $pms, $regex) = @_;

    return 0 unless $self->{freemail_available};

    my $rulename = $pms->get_current_eval_rule_name();
    dbg("RULE ($rulename) check_freemail_from".(defined $regex ? " regex:$regex" : ""));

    my $re;
    if (defined $regex) {
        my ($rec, $err) = compile_regexp($regex, 0);
        if (!$rec) {
            warn "freemail: invalid regexp for $rulename '$regex': $err\n";
            return 0;
        }
        $re = $rec;
    }

    my %from_addrs = map { lc($_) => 1 } ($pms->all_from_addrs());
    delete $from_addrs{''}; # no empty ones thx

    unless (scalar keys %from_addrs) {
        dbg("no from-addresses found to check");
        return 0;
    }

    dbg("all from-addresses: ".join(', ', keys %from_addrs));

    foreach my $email (keys %from_addrs) {
        next unless $self->_is_freemail($email, $pms);
        if (defined $re) {
            next unless $email =~ /$re/o;
            dbg("HIT! $email is freemail and matches regex");
        }
        else {
            dbg("HIT! $email is freemail");
        }
        $self->_test_log($pms, $email, $rulename);
        return 1;
    }

    return 0;
}

sub check_freemail_replyto {
    my ($self, $pms, $what) = @_;

    return 0 unless $self->{freemail_available};

    my $rulename = $pms->get_current_eval_rule_name();
    dbg("RULE ($rulename) check_freemail_replyto");

    if (defined $what) {
        if ($what ne 'replyto' and $what ne 'reply') {
            warn("freemail: invalid check_freemail_replyto option: $what\n");
            return 0;
        }
    }
    else {
        $what = 'replyto';
    }

    # Skip mailing-list etc looking requests, mostly FPs from them
    if ($pms->{main}->{conf}->{freemail_skip_bulk_envfrom}) {
        my $envfrom = ($pms->get("EnvelopeFrom"))[0];
        if (defined $envfrom && $envfrom =~ $skip_replyto_envfrom) {
            dbg("envelope sender looks bulk, skipping check: $envfrom");
            return 0;
        }
    }

    my @from_addrs = map (lc, $pms->get("From:addr"));
    dbg("From address: ".join(", ", @from_addrs)) if @from_addrs;

    my @replyto_addrs = map (lc, $pms->get("Reply-To:addr"));
    dbg("Reply-To address: ".join(", ", @replyto_addrs)) if @replyto_addrs;

    my $from_is_fm = grep { $self->_is_freemail($_, $pms) } @from_addrs;
    my $replyto_is_fm = grep { $self->_is_freemail($_, $pms) } @replyto_addrs;

    my $from_not_in_replyto = 1;
    foreach my $from (@from_addrs) {
        next unless grep { $_ eq $from } @replyto_addrs;
        $from_not_in_replyto = 0;
    }

    if ($from_is_fm and $replyto_is_fm and $from_not_in_replyto) {
        dbg("HIT! From and Reply-To are different freemails");
        my $from = join(",", @from_addrs);
        my $replyto = join(",", @replyto_addrs);
        $self->_test_log($pms, "$from -> $replyto", $rulename);
        return 1;
    }

    if ($what eq 'replyto') {
        if (!$replyto_is_fm) {
            dbg("Reply-To is not freemail, skipping check");
            return 0;
        }
    }
    elsif ($what eq 'reply') {
        if (@replyto_addrs and !$replyto_is_fm) {
            dbg("Reply-To defined and is not freemail, skipping check");
            return 0;
        }
        elsif (!$from_is_fm) {
            dbg("No Reply-To and From is not freemail, skipping check");
            return 0;
        }
    }

    return 0 unless $self->_parse_body($pms);

    # Compare body to headers
    if (scalar keys %{$pms->{freemail_cache}{body}}) {
        my $reply_addrs = $what eq 'replyto' ? \@replyto_addrs :
                              $replyto_is_fm ? \@replyto_addrs : \@from_addrs;
        dbg("comparing to body freemails: ".join(", ", @$reply_addrs));
        foreach my $body_email (keys %{$pms->{freemail_cache}{body}}) {
            foreach my $reply_email (@$reply_addrs) {
                if ($body_email ne $reply_email) {
                    dbg("HIT! $reply_email (Reply) and $body_email (Body) are different freemails");
                    $self->_test_log($pms, "$reply_email, $body_email", $rulename);
                    return 1;
                }
            }
        }
    }

    return 0;
}

1;
