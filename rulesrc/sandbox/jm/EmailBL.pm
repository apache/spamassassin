package Mail::SpamAssassin::Plugin::EmailBL;
my $VERSION = 0.16;

### Blah:
#
# Author: Henrik Krohns <sa@hege.li>
# Copyright 2009 Henrik Krohns
#
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
#

### About:
#
# This plugin creates rbl style DNS lookups for emails.
# There isn't any official emailbl standard yet(?) so we:
#
# 1) make md5hash of lowercased email (no other normalizations)
# 2) lookup <hexmd5hash>.zone.example.com.
#

### Supported .cf clauses:
#
# loadplugin Mail::SpamAssassin::Plugin::EmailBL EmailBL.pm
#
# emailbl_acl_<aclname> [!]email/domain ...
#
#    Where <aclname> is 1-32 character alphanumeric (a-z0-9) identifier.
#    Exclamation in front of email/domain excludes it from lookup.
#    No wildcards or subdomains of any kind, everything must be literal.
#
#    To allow check of some hotmail domains, excluding your own email:
#    emailbl_acl_hotmail !myuser@hotmail.com hotmail.com hotmail.co.uk
#
#    You can add exclusions to special acl 'all' when you are checking
#    all domains without using acl, but need to have exceptions.
#
# header EBL_TEST eval:check_emailbl('aclname[-option]', 'zone' [, 'sub-test'])
# tflags EBL_TEST net
#
#    First argument is <aclname> with possible option. Special acl of 'all'
#    can be used to allow lookup every email (do not use unless used emailbl
#    allows it!). Option can be appended after acl with dash.
#
#    Supported options:
#
#    aclname-all        all (headers+bodysafe) is the default
#    aclname-from       From header only
#    aclname-replyto    Reply-To header only
#    aclname-envfrom    EnvelopeFrom header (e.g. Return-Path)
#    aclname-headers    all three headers above
#    aclname-reply      header used to reply (Reply-To > From > Return-Path)
#    aclname-body       body
#    aclname-bodysafe   body, using simpler/safer regex to reduce(?) FPs
#
#    Zone is the DNS zone, e.g. 'ebl.example.com.' (customary to add ending dot)
#
#    Sub-test is regex matching the returned IP address, e.g. '127.0.0.[234]'.
#    It defaults to '127\.\d+\.\d+\.\d+' (anything starting with 127).
#
#    There is no limit on mixing and matching multiple check_emailbl rules, acls
#    and zones.
#

### Changelog:
#
# 0.16 - first public version
#

use strict;
use Mail::SpamAssassin::Plugin;
use Net::DNS;
use Digest::MD5 qw(md5_hex);

use vars qw(@ISA);
@ISA = qw(Mail::SpamAssassin::Plugin);

# TLDs generated from RegistrarBoundaries.pm VALID_TLDS 2008020601
my $tlds = '(?:m(?:[acdeghkmnpqrstvwxyz]|u(?:seum)?|o(?:bi)?|i?l)|a(?:[cdfgilmnoqtuwxz]|e(?:ro)?|r(?:pa)?|s(?:ia)?)|c(?:[cdfghiklmnruvxyz]|o(?:op|m)?|at?)|t(?:[cdfghjkmnoptvwz]|r(?:avel)?|e?l)|n(?:[cfgilopruz]|a(?:me)?|et?)|b(?:[abdefghjmnorstwyz]|iz?)|g(?:[adefghilmnpqrstuwy]|ov)|i(?:[delmoqrst]|n(?:fo|t)?)|p(?:[aefghklnstwy]|ro?)|s[abcdeghiklmnrtuvyz]|j(?:[emp]|o(?:bs)?)|e(?:[cegrst]|d?u)|k[eghimnprwyz]|l[abcikrstuvy]|v[aceginu]|d[ejkmoz]|f[ijkmor]|h[kmnrtu]|o(?:rg|m)|u[agksyz]|r[eosuw]|z[amw]|w[fs]|y[eu]|qa)';

### Some regexp tips courtesy of http://www.regular-expressions.info/email.html
### v 0.02
# full email regex
my $email_regex = qr/
  (?=.{0,64}\@)                         # limit userpart to 64 chars (and speed up searching?)
  (?<![a-z0-9!#$%&'*+\/=?^_`{|}~-])     # start boundary
  (                                     # capture email
  [a-z0-9!#$%&'*+\/=?^_`{|}~-]+         # no dot in beginning
  (?:\.[a-z0-9!#$%&'*+\/=?^_`{|}~-]+)*  # no consecutive dots, no ending dot
  \@
  (?:[a-z0-9](?:[a-z0-9-]{0,59}[a-z0-9])?\.){1,4} # max 4x61 char parts (should be enough?)
  ${tlds}                               # ends with valid tld
  )
  (?!(?:[a-z0-9-]|\.[a-z0-9]))          # make sure domain ends here
/xi;
# safe email regex (limit username chars)
my $email_safe_regex = qr/
  (?=.{0,64}\@)                         # limit userpart to 64 chars (and speed up searching?)
  (?<![a-z0-9!#$%&'*+\/=?^_`{|}~-])     # start boundary
  (                                             # capture email
  [a-z0-9_-]+                           # no dot in beginning
  (?:\.[a-z0-9_-]+)*                    # no consecutive dots, no ending dot
  \@
  (?:[a-z0-9](?:[a-z0-9-]{0,59}[a-z0-9])?\.){1,4} # max 4x61 char parts (should be enough?)
  ${tlds}                               # ends with valid tld
  )
  (?!(?:[a-z0-9-]|\.[a-z0-9]))          # make sure domain ends here
/xi;
# default email whitelist
my $email_whitelist = qr/
  ^(?:
      abuse|support|sales|info|helpdesk
    | (?:post|host|domain)master
    | request-[a-f0-9]{16}              # live.com
    | bounced?-                         # yahoo.com etc
    | [a-f0-9]{8}(?:\.[a-f0-9]{8}|-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}) # gmail msgids?
    | .+=.+=.+                          # gmail forward
  )\@
/xi;


sub dbg { Mail::SpamAssassin::Plugin::dbg ("EmailBL: @_"); }

sub new
{
    my ($class, $mailsa) = @_;

    $class = ref($class) || $class;
    my $self = $class->SUPER::new($mailsa);
    bless ($self, $class);

    $self->{EmailBL_available} = 1;
    if ($mailsa->{local_tests_only}) {
        $self->{EmailBL_available} = 0;
        dbg("only local tests enabled, plugin disabled");
    }

    $self->set_config($mailsa->{conf});
    $self->register_eval_rule("check_emailbl");

    return $self;
}

sub set_config {
    my ($self, $conf) = @_;
    my @cmds = ();
    push(@cmds, {
        setting => 'emailbl_add_describe_email',
        default => 1,
        type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
        }
    );
    $conf->{parser}->register_commands(\@cmds);
}

sub parse_config {
    my ($self, $opts) = @_;

    if ($opts->{key} =~ /^emailbl_acl_([a-z0-9]{1,32})$/i) {
        $self->inhibit_further_callbacks();
        return 1 unless $self->{EmailBL_available};

        my $acl = lc($1);
        foreach my $temp (split(/\s+/, $opts->{value}))
        {
            if ($temp =~ /^(\!)?([a-z0-9.\@-]+)$/i) {
                my $neg = $1;
                my $value = lc($2);
                if (defined $neg) {
                    $self->{emailbl_acl}{$acl}{$value} = 0;
                }
                else {
                    next if $acl eq 'all'; # only exclusions for 'all'
                    # exclusions override inclusions
                    $self->{emailbl_acl}{$acl}{$value} = 1
                        unless defined $self->{emailbl_acl}{$acl}{$value};
                }
            }
            else {
                warn("invalid acl: $temp");
            }
        }

        return 1;
    }

    return 0;
}

sub finish_parsing_end
{
    my ($self, $opts) = @_;

    return 0 unless $self->{EmailBL_available};

    foreach my $acl (keys %{$self->{emailbl_acl}}) {
        my $values = scalar keys %{$self->{emailbl_acl}{$acl}};
        dbg("loaded acl $acl with $values entries");
    }

    return 0;
}

# parse eval rule args
sub _parse_args {
    my ($self, $acl, $zone, $zone_match) = @_;

    if (not defined $zone) {
        warn("acl and zone must be specified for rule");
        return ();
    }

    # acl
    $acl =~ s/\s+//g; $acl = lc($acl);
    ($acl, my $what) = split('-', $acl, 2);
    if ($acl !~ /^[a-z0-9]{1,32}$/) {
        warn("invalid acl definition: $acl");
        return ();
    }
    if ($acl ne 'all' and not defined $self->{emailbl_acl}{$acl}) {
        warn("no such acl defined: $acl");
        return ();
    }
    if (defined $what) {
        unless ($what =~ /^(?:all|body(?:safe)?|headers|from|reply|replyto|envfrom)$/) {
            warn("invalid acl argument: $acl");
            return ();
        }
    }
    else {
        $what = 'all'; #default
    }

    # zone
    $zone =~ s/\s+//g; $zone = lc($zone);
    unless ($zone =~ /^[a-z0-9_.-]+$/) {
        warn("invalid zone definition: $zone");
        return ();
    }

    # zone_match
    if (defined $zone_match) {
        my $tst = eval { qr/$zone_match/ };
        if ($@) {
            warn("invalid match regex: $zone_match");
            return ();
        }
    }
    else {
        $zone_match = '127\.\d+\.\d+\.\d+';
    }

    return ($acl, $what, $zone, $zone_match);
}

sub _add_desc {
    my ($self, $pms, $email, $desc) = @_;

    my $rulename = $pms->get_current_eval_rule_name();
    if (not defined $pms->{conf}->{descriptions}->{$rulename}) {
        $pms->{conf}->{descriptions}->{$rulename} = $desc;
    }
    if ($pms->{main}->{conf}->{emailbl_add_describe_email}) {
        $email =~ s/\@/[at]/g;
        $pms->{conf}->{descriptions}->{$rulename} .= " ($email)";
    }
}
                                                
# return:
# 0 to deny email/domain
# 1 to allow email/domain
sub _acl_allow {
    my ($self, $prs, $email) = @_;

    my $domain = $email;
    $domain =~ s/.*\@//;
    if (defined $self->{emailbl_acl}{"$prs->{acl}"}{$email}) {
        return 1 if $self->{emailbl_acl}{"$prs->{acl}"}{$email};
        dbg("acl: denying check of $email");
        return 0;
    }
    if (defined $self->{emailbl_acl}{"$prs->{acl}"}{$domain}) {
        return 1 if $self->{emailbl_acl}{"$prs->{acl}"}{$domain};
        dbg("acl: denying check of $domain");
        return 0;
    }
    return 1 if $prs->{acl} eq 'all';
    dbg("acl: denying check of $email (no acl matched)");
    return 0;
}

# hash and lookup array of emails
sub _lookup {
    my ($self, $pms, $prs, $emails) = @_;

    return 0 unless defined @$emails;

    my %digests = map { md5_hex($_) => $_ } @$emails;
    my $dcnt = scalar keys %digests;

    # nothing to do?
    return 0 unless $dcnt;

    # todo async lookup and proper timeout
    my $timeout = int(10 / $dcnt);
    $timeout = 3 if $timeout < 3;

    my $resolver = Net::DNS::Resolver->new(
        udp_timeout => $timeout,
        tcp_timeout => $timeout,
        retrans => 0,
        retry => 1,
        persistent_tcp => 0,
        persistent_udp => 0,
        dnsrch => 0,
        defnames => 0,
    );

    foreach my $digest (keys %digests) {
        my $email = $digests{$digest};

        # if cached
        if (defined $pms->{emailbl_lookup_cache}{"$digest.$prs->{zone}"}) {
            my $addr = $pms->{emailbl_lookup_cache}{"$digest.$prs->{zone}"};
            dbg("lookup: $digest.$prs->{zone} ($email) [cached]");
            return 0 if ($addr eq '');
            if ($addr =~ $prs->{zone_match}) {
                dbg("HIT! $digest.$prs->{zone} = $addr ($email)");
                $self->_add_desc($pms, $email, "EmailBL hit at $prs->{zone}");
                return 1;
            }
            return 0;
        }

        dbg("lookup: $digest.$prs->{zone} ($email)");
        my $query = $resolver->query("$digest.$prs->{zone}", 'A');
        if (not defined $query) {
            if ($resolver->errorstring ne 'NOERROR' &&
                $resolver->errorstring ne 'NXDOMAIN') {
                dbg("DNS error? ($resolver->{errorstring})");
            }
            $pms->{emailbl_lookup_cache}{"$digest.$prs->{zone}"} = '';
            next;
        }
        foreach my $rr ($query->answer) {
            if ($rr->type ne 'A') {
                dbg("got answer of wrong type? ($rr->{type})");
                next;
            }
            if (defined $rr->address && $rr->address ne '') {
                $pms->{emailbl_lookup_cache}{"$digest.$prs->{zone}"} = $rr->address;
                if ($rr->address =~ $prs->{zone_match}) {
                    dbg("HIT! $digest.$prs->{zone} = $rr->{address} ($email)");
                    $self->_add_desc($pms, $email, "EmailBL hit at $prs->{zone}");
                    return 1;
                }
                else {
                    dbg("got answer, but not matching $prs->{zone_match} ($rr->{address})");
                }
            }
            else {
                dbg("got answer but no IP? ($resolver->{errorstring})");
            }
        }
    }

    return 0;
}

sub _quick_check {
    my ($self, $pms, $prs, $email) = @_;

    return 0 if (not defined $email or $email eq '');

    if (defined $prs->{emailbl_whitelist}{$email}) {
        dbg("$prs->{what} address whitelisted, it's also recipient: $email");
        return 0;
    }
    if ($email =~ $email_whitelist) {
        dbg("$prs->{what} address whitelisted, default: $email");
        return 0;
    }
    return 0 unless $self->_acl_allow($prs, $email);
    return $self->_lookup($pms, $prs, [$email]);
}

sub _emailbl {
    my ($self, $pms, $acl, $what, $zone, $zone_match) = @_;

    my $prs = {}; # per rule state
    $prs->{acl} = $acl;
    $prs->{what} = $what;
    $prs->{zone} = $zone;
    $prs->{zone_match} = $zone_match;
    $prs->{rulename} = $pms->get_current_eval_rule_name();

    dbg("RULE ($prs->{rulename}) acl:$prs->{acl} emails:$prs->{what} zone:$prs->{zone} match:$prs->{zone_match}");

    # create whitelist
    # we don't want to match the actual recipient address anywhere
    unless (defined $prs->{emailbl_whitelist}) {
        %{$prs->{emailbl_whitelist}} = map { lc($_) => 1 }
            ( $pms->get("X-Original-To:addr"),
              $pms->get("Apparently-To:addr"),
              $pms->get("Delivered-To:addr"),
              $pms->get("Envelope-To:addr"),
              'ignore@compiling.spamassassin.taint.org', # --lint etc
            );
        delete $prs->{emailbl_whitelist}{''}; # no empty ones thx
    }

    # check only envfrom?
    my $envfrom = lc($pms->get("EnvelopeFrom:addr"));
    if ($prs->{what} eq 'envfrom') {
        return $self->_quick_check($pms, $prs, $envfrom);
    }

    # check only from?
    my $from = lc($pms->get("From:addr"));
    if ($prs->{what} eq 'from') {
        return $self->_quick_check($pms, $prs, $from);
    }

    # check only replyto?
    my $replyto = lc($pms->get("Reply-To:addr"));
    if ($prs->{what} eq 'replyto') {
        return $self->_quick_check($pms, $prs, $replyto);
    }

    # check the most likely reply address, reply-to > from > envfrom
    if ($prs->{what} eq 'reply') {
        my $email;
        if ($replyto ne '') { $email = $replyto; }
        elsif ($from ne '') { $email = $from; }
        else { $email = $envfrom; }
        return $self->_quick_check($pms, $prs, $email);
    }

    my @lookup_headers;

    # parse headers
    if ($prs->{what} eq 'all' or $prs->{what} eq 'headers') {
        if (not defined $pms->{emailbl_cache}{headers}) {
            %{$pms->{emailbl_cache}{headers}} = ();
            # merge all possible sender headers
            my %emails_headers = map { $_ => 1 }
                ($envfrom, $from, $replyto);
            delete $emails_headers{''}; # no empty ones thx
            foreach my $email (keys %emails_headers) {
                if (defined $prs->{emailbl_whitelist}{$email}) {
                    dbg("header address whitelisted, it's also recipient: $email");
                    next;
                }
                if ($email =~ $email_whitelist) {
                    dbg("header address whitelisted, default: $email");
                    next;
                }
                $pms->{emailbl_cache}{headers}{$email} = 1;
            }
            dbg("all emails from headers: ".join(', ', keys %emails_headers))
                if scalar keys %emails_headers;
        }
        foreach my $email (keys %{$pms->{emailbl_cache}{headers}}) {
            next unless $self->_acl_allow($prs, $email);
            push @lookup_headers, $email;
        }
        # check only headers?
        if ($prs->{what} eq 'headers') {
            return $self->_lookup($pms, $prs, \@lookup_headers);
        }
    }

    my @lookup_body;

    # parse body
    if ($prs->{what} eq 'all' or $prs->{what} eq 'body' or $prs->{what} eq 'bodysafe') {
        # if not cached
        my $safe = ($prs->{what} eq 'all' or $prs->{what} eq 'bodysafe') ? 'safe' : '';
        if (not defined $pms->{emailbl_cache}{"body$safe"}) {
            %{$pms->{emailbl_cache}{"body$safe"}} = ();
            my %all;
            my $emailre = ($prs->{what} eq 'all' or $prs->{what} eq 'bodysafe') ?
                $email_safe_regex : $email_regex;
            my $body = $pms->get_decoded_stripped_body_text_array();
            BODY: foreach (@$body) {
                # strip urls with possible emails inside
                s#<?https?://\S{0,255}\@\S{0,255}# #gi;
                # strip emails contained in <>, except <mailto:>
                # also strip ones followed by quote-like "wrote:" (but not fax: and tel: etc)
                #s#<?(?<!mailto:)${emailre}(?:>|\s{1,10}(?!(?:fa(?:x|csi)|tel|phone|e?-?mail))[a-z]{2,11}:)# #gi;
                while (/$emailre/g) {
                    my $email = lc($1);
                    $all{$email} = 1;
                    if (defined $prs->{emailbl_whitelist}{$email}) {
                        dbg("body$safe address whitelisted, it's also recipient: $email");
                        next;
                    }
                    if ($email =~ $email_whitelist) {
                        dbg("body$safe address whitelisted, default: $email");
                        next;
                    }
                    $pms->{emailbl_cache}{"body$safe"}{$email} = 1;
                    my $hsh = $pms->{emailbl_cache}{"body$safe"};
                    # hard limit, maybe better would be to get some first and last ones
                    last BODY if scalar keys %$hsh >= 3;
                }
            }
            dbg("all emails from body$safe: ".join(', ', keys %all)) if %all;
        }
        foreach my $email (keys %{$pms->{emailbl_cache}{"body$safe"}}) {
            next unless $self->_acl_allow($prs, $email);
            push @lookup_body, $email;
        }
        # check only body?
        if ($prs->{what} eq 'body' or $prs->{what} eq 'bodysafe') {
            return $self->_lookup($pms, $prs, \@lookup_body);
        }
    }

    # daa
    if ($prs->{what} eq 'all') {
        my %all = map { $_ => 1 } (@lookup_headers, @lookup_body);
        my @lookup_all = keys %all;
        return $self->_lookup($pms, $prs, \@lookup_all);
    }

    return 0;
}

sub check_emailbl {
    my ($self, $pms, @args) = @_;

    return 0 unless $self->{EmailBL_available};
    return 0 unless (@args = $self->_parse_args(@args));
    return _emailbl($self, $pms, @args);
}

1;

