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

Mail::SpamAssassin::Plugin::ARC - perform ARC verification tests

=head1 SYNOPSIS

 loadplugin Mail::SpamAssassin::Plugin::ARC [/path/to/ARC.pm]

 full   ARC_SIGNED            eval:check_arc_signed()
 full   ARC_VALID             eval:check_arc_valid()
 full   ARC_TRUSTED           eval:check_arc_trusted()

=head1 DESCRIPTION

This SpamAssassin plugin implements ARC (Authenticated Received Chain)
verification as described by RFC 8617.

If the C<AuthRes> plugin is loaded and has parsed C<arc=> results from
Authentication-Results headers, those results will be re-used and native
verification is skipped.  Otherwise, the plugin performs its own
cryptographic verification using the C<Mail::DKIM::ARC::Verifier> module
(version 0.50 or later required).

=head1 SEE ALSO

C<Mail::DKIM> Mail::SpamAssassin::Plugin(3)

  https://www.rfc-editor.org/rfc/rfc8617

=cut

package Mail::SpamAssassin::Plugin::ARC;

use Mail::SpamAssassin::Plugin;
use Mail::SpamAssassin::Logger;
use Mail::SpamAssassin::Timeout;
use Mail::SpamAssassin::Header::ArcAuthenticationResults;
use version;

use strict;
use warnings;
use re 'taint';

our @ISA = qw(Mail::SpamAssassin::Plugin);

sub new {
  my $class = shift;
  my $mailsaobject = shift;

  $class = ref($class) || $class;
  my $self = $class->SUPER::new($mailsaobject);
  bless ($self, $class);

  $self->register_eval_rule("check_arc_signed", $Mail::SpamAssassin::Conf::TYPE_FULL_EVALS);
  $self->register_eval_rule("check_arc_valid", $Mail::SpamAssassin::Conf::TYPE_FULL_EVALS);
  $self->register_eval_rule("check_arc_trusted", $Mail::SpamAssassin::Conf::TYPE_FULL_EVALS);

  # run after AuthRes (-20) so we can re-use arc= results,
  # but before DKIM, SPF, DMARC (0) so arc_auth_results is available
  $self->register_method_priority("parsed_metadata", -10);

  $self->set_config($mailsaobject->{conf});

  return $self;
}

###########################################################################

sub set_config {
  my($self, $conf) = @_;
  my @cmds;

=head1 USER SETTINGS

=over 4

=item arc_timeout n             (default: 5)

Timeout in seconds for ARC signature verification. If Mail::DKIM cannot
complete verification within this time, the ARC check will be aborted.

=item arc_trusted_sealers domain1 domain2 ...

Specify domains that are trusted as ARC sealers.  When the ARC chain is
cryptographically valid, the plugin will parse ARC-Authentication-Results
headers from trusted sealers and make them available to other plugins
(such as DMARC) via C<$pms-E<gt>{arc_auth_results}>.  ARC instances sealed
by untrusted domains are ignored.

If no trusted sealers are configured, ARC-Authentication-Results headers
will not be parsed.

Can be specified multiple times, additional entries are appended.

  arc_trusted_sealers google.com microsoft.com
  arc_trusted_sealers yahoo.com

=back

=cut

  push(@cmds, {
    setting => 'arc_timeout',
    default => 5,
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_NUMERIC,
  });

  push(@cmds, {
    setting => 'arc_trusted_sealers',
    default => {},
    type => $Mail::SpamAssassin::Conf::CONF_TYPE_HASH_KEY_VALUE,
    code => sub {
      my ($self, $key, $value, $line) = @_;
      if (!defined $value || $value =~ /^$/) {
        return $Mail::SpamAssassin::Conf::MISSING_REQUIRED_VALUE;
      }
      foreach my $domain (split(/\s+/, lc $value)) {
        $self->{arc_trusted_sealers}->{$domain} = 1;
      }
    }
  });

  $conf->{parser}->register_commands(\@cmds);
}

###########################################################################

sub parsed_metadata {
  my ($self, $opts) = @_;
  my $pms = $opts->{permsgstatus};

  my(@arc_signatures, @arc_valid_signatures);

  $pms->{arc_signatures_ready} = 0;
  $pms->{arc_signatures_dependable} = 0;
  $pms->{arc_signatures} = \@arc_signatures;
  $pms->{arc_valid_signatures} = \@arc_valid_signatures;
  $pms->{arc_signed} = 0;
  $pms->{arc_valid} = 0;

  my $suppl_attrib = $pms->{msg}->{suppl_attrib};
  if (defined $suppl_attrib && exists $suppl_attrib->{arc_signatures}) {
    my $provided_arc_signatures = $suppl_attrib->{arc_signatures};
    if (ref $provided_arc_signatures) {
      @arc_signatures = @$provided_arc_signatures;
      $pms->{arc_signatures_ready} = 1;
      $pms->{arc_signatures_dependable} = 1;
      dbg("arc: ARC signatures provided by the caller, %d signatures",
          scalar(@arc_signatures));
    }
  }

  if ($pms->{arc_signatures_ready}) {
    $self->_check_arc_valid_signature($pms, \@arc_signatures);
  } elsif ($self->_check_arc_from_authres($pms)) {
    # re-used ARC results from AuthRes plugin
  } elsif (!$pms->is_dns_available()) {
    dbg("arc: signature verification disabled, DNS resolving not available");
  } elsif (!$self->_arc_load_modules()) {
    # Mail::DKIM::ARC module not available
  } else {
    my $timemethod = $self->{main}->time_method("check_arc_signature");
    my $arc_verifier = Mail::DKIM::ARC::Verifier->new;
    $self->_check_signature($pms, $arc_verifier, \@arc_signatures);
  }
}

sub check_arc_signed {
  my ($self, $pms, $full_ref, @acceptable_domains) = @_;
  my $result = 0;
  if (!$pms->{arc_signed}) {
    # don't bother
  } elsif (!@acceptable_domains) {
    $result = 1;  # no additional constraints, any signing domain will do
  }
  return $result;
}

sub check_arc_valid {
  my ($self, $pms, $full_ref, @acceptable_domains) = @_;
  my $result = 0;
  if (!$pms->{arc_valid}) {
    # don't bother
  } elsif (!@acceptable_domains) {
    $result = 1;  # no additional constraints, any signing domain will do,
                  # also any signing key size will do
  }
  return $result;
}

sub check_arc_trusted {
  my ($self, $pms) = @_;
  return $pms->{arc_auth_results} ? 1 : 0;
}

sub _check_arc_from_authres {
  my ($self, $pms) = @_;

  return 0 if !$pms->{authres_parsed} || !$pms->{authres_parsed}{arc}
              || !@{$pms->{authres_parsed}{arc}};

  dbg("arc: checking for AuthRes plugin ARC results");

  foreach my $arc_result (@{$pms->{authres_parsed}{arc}}) {
    my $result = lc($arc_result->{result} || '');
    next unless $result =~ /^(pass|fail|none)$/;

    dbg("arc: re-using result from AuthRes plugin: %s", $result);

    if ($result eq 'pass') {
      $pms->{arc_signed} = 1;
      $pms->{arc_valid} = 1;
      $self->_parse_trusted_aar_from_headers($pms);
    } elsif ($result eq 'fail') {
      $pms->{arc_signed} = 1;
    }

    return 1;
  }

  return 0;
}

# ---------------------------------------------------------------------------

sub _arc_load_modules {
  my ($self) = @_;

  if (!$self->{tried_loading}) {
    $self->{service_available} = 0;
    my $timemethod = $self->{main}->time_method("arc_load_modules");
    my $eval_stat;
    eval {
      { require Mail::DKIM::ARC::Verifier }
      1;
    } or do {
      $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
    };
    $self->{tried_loading} = 1;

    if (defined $eval_stat) {
      dbg("arc: cannot load Mail::DKIM::ARC::Verifier module, ARC checks disabled: %s",
          $eval_stat);
    } else {
      my $version = Mail::DKIM::ARC::Verifier->VERSION;
      dbg("arc: using Mail::DKIM::ARC::Verifier version $version");
      if (version->parse($version) >= version->parse(0.40)) {
        # Let Mail::DKIM use our interface to Net::DNS::Resolver.
        my $res = $self->{main}->{resolver};
        dbg("arc: providing our own resolver: %s", ref $res);
        Mail::DKIM::DNS::resolver($res);
      }
      $self->{service_available} = 1;
    }
  }
  return $self->{service_available};
}

sub _check_signature {
  my($self, $pms, $verifier, $signatures) = @_;

  my $conf = $pms->{conf};
  if (!$verifier) {
    dbg("arc: cannot create Mail::DKIM::ARC::Verifier object");
    return;
  }
  $pms->{arc_verifier} = $verifier;

  eval {
    my $str = $pms->{msg}->get_pristine();
    if ($pms->{msg}->{line_ending} eq "\015\012") {
      $verifier->PRINT($str);
    } else {
      $str =~ s/\012/\015\012/gs;
      $verifier->PRINT($str);
      undef $str;
    }
    1;
  } or do {
    my $eval_stat = $@ ne '' ? $@ : "errno=$!";  chomp $eval_stat;
    dbg("arc: verification failed, intercepted error: $eval_stat");
    return 0;
  };

  my $timeout = $conf->{arc_timeout};
  my $timer = Mail::SpamAssassin::Timeout->new(
                { secs => $timeout, deadline => $pms->{master_deadline} });

  my $err = $timer->run_and_catch(sub {
    dbg("arc: performing public ARC key lookup and signature verification");
    $verifier->CLOSE();

    @$signatures = $verifier->UNIVERSAL::can("signatures") ?
                               $verifier->signatures : $verifier->signature;
  });
  if ($timer->timed_out()) {
    dbg("arc: public key lookup or verification timed out after %s s",
        $timeout);
  } elsif ($err) {
    chomp $err;
    dbg("arc: ARC public key lookup or verification failed: $err");
  }

  $pms->{arc_signatures_ready} = 1;
  if (!@$signatures || !$pms->{tests_already_hit}->{'__TRUNCATED'}) {
    $pms->{arc_signatures_dependable} = 1;
  }
  $self->_check_arc_valid_signature($pms, \@$signatures);
}

sub _check_arc_valid_signature {
  my($self, $pms, $signatures) = @_;

  my(@valid_signatures);
  my $conf = $pms->{conf};
  my @arc_sig;

  if ($pms->{arc_signatures_ready}) {
    foreach my $signature (@$signatures) {
      next if !defined $signature;
      next if !defined $signature->selector || $signature->selector eq "";

      my($info, $valid, $expired);
      $valid = $signature->result eq 'pass';
      $info = $valid ? 'VALID' : 'FAILED';
      if ($valid && $signature->UNIVERSAL::can("check_expiration")) {
        $expired = !$signature->check_expiration;
        $info .= ' EXPIRED' if $expired;
      }

      my %arc;
      $arc{prefix} = $signature->prefix;
      $arc{valid} = $valid;
      push(@arc_sig, \%arc);

      push(@valid_signatures, $signature) if $valid && !$expired;

      if (would_log("dbg","arc")) {
        my $d = $signature->domain;
        dbg("arc: %s i=%s %s d=%s, s=%s, a=%s, c=%s, %s",
          $info, $signature->instance, $signature->prefix,
          map(!defined $_ ? '(undef)' : $_,
            $d, $signature->selector,
            $signature->algorithm, scalar($signature->canonicalization),
            $signature->result),
        );
      }
    }

    if (@valid_signatures) {
      $pms->{arc_signed} = 1;
      my $arc_seal_valid = 0;
      my $arc_message_valid = 0;
      my $arc_message_found = 0;
      # All ARC-Seals signatures and the most recent ARC-Message-Signature must be valid
      foreach my $arc ( @arc_sig ) {
        if ($arc->{prefix} eq 'ARC-Message-Signature:') {
          next if $arc_message_found;
          $arc_message_valid = 1 if $arc->{valid};
          $arc_message_found = 1;
        }
        if ($arc->{prefix} eq 'ARC-Seal:') {
          if ($arc->{valid}) {
            $arc_seal_valid = 1;
          } else {
            $arc_seal_valid = 0;
            last;
          }
        }
      }
      if ($arc_message_valid and $arc_seal_valid) {
        $pms->{arc_valid} = 1;
        $self->_parse_trusted_aar($pms);
      }
      my $sig = $valid_signatures[0];
      my $sig_res = $sig->result_detail;
      dbg("arc: ARC signature verification result: %s", uc($sig_res));

    } elsif (@$signatures) {
      $pms->{arc_signed} = 1;
      my $sig = @$signatures[0];
      my $sig_res = $sig->result_detail;
      dbg("arc: ARC signature verification result: %s", uc($sig_res));

    } else {
      dbg("arc: ARC signature verification result: none");
    }
  }
}

sub _parse_trusted_aar {
  my ($self, $pms) = @_;

  my $trusted = $pms->{conf}->{arc_trusted_sealers};
  return if !$trusted || !%$trusted;

  my $verifier = $pms->{arc_verifier};
  return if !ref($verifier) || !defined $verifier->{seals};

  # Build set of ARC instance indices with trusted seal domains
  my %trusted_indices;
  foreach my $seal (@{$verifier->{seals}}) {
    my $d = $seal->{tags_by_name}{d}{value};
    my $i = $seal->{tags_by_name}{i}{value};
    next if !defined $d || !defined $i;
    if ($trusted->{lc $d}) {
      $trusted_indices{$i} = 1;
      dbg("arc: seal i=%s d=%s is trusted", $i, $d);
    } else {
      dbg("arc: seal i=%s d=%s is not trusted", $i, $d);
    }
  }
  return if !%trusted_indices;

  $self->_parse_aar_by_trusted_indices($pms, \%trusted_indices);
}

sub _parse_trusted_aar_from_headers {
  my ($self, $pms) = @_;

  my $trusted = $pms->{conf}->{arc_trusted_sealers};
  return if !$trusted || !%$trusted;

  # Build set of ARC instance indices from ARC-Seal headers
  my %trusted_indices;
  my @seals = $pms->{msg}->get_pristine_header('ARC-Seal');
  foreach my $seal (@seals) {
    chomp $seal;
    my ($i) = $seal =~ /\bi\s*=\s*(\d+)/;
    my ($d) = $seal =~ /\bd\s*=\s*([^\s;]+)/;
    next if !defined $d || !defined $i;
    if ($trusted->{lc $d}) {
      $trusted_indices{$i} = 1;
      dbg("arc: seal i=%s d=%s is trusted", $i, $d);
    } else {
      dbg("arc: seal i=%s d=%s is not trusted", $i, $d);
    }
  }
  return if !%trusted_indices;

  $self->_parse_aar_by_trusted_indices($pms, \%trusted_indices);
}

sub _parse_aar_by_trusted_indices {
  my ($self, $pms, $trusted_indices) = @_;

  # Parse ARC-Authentication-Results headers from trusted sealers
  my @aar = $pms->{msg}->get_pristine_header('ARC-Authentication-Results');
  return if !@aar;

  my @arc_auth_results;
  foreach my $hdr (@aar) {
    chomp $hdr;

    my $ar = eval {
      Mail::SpamAssassin::Header::ArcAuthenticationResults->new($hdr);
    };
    if ($@ || !$ar) {
      dbg("arc: failed to parse AAR header: %s", $@ || 'unknown error');
      next;
    }

    my $arc_index = $ar->arc_index();
    if (!defined $arc_index) {
      dbg("arc: AAR header missing i= tag, skipping");
      next;
    }

    if (!$trusted_indices->{$arc_index}) {
      dbg("arc: AAR i=%s not from trusted sealer, skipping", $arc_index);
      next;
    }

    my $authserv = $ar->authserv_id();
    my %results;
    foreach my $method ($ar->methods()) {
      foreach my $m ($ar->method($method)) {
        $results{$method} = {
          result     => $m->{result},
          reason     => $m->{reason},
          properties => $m->{properties},
        };
      }
    }

    push @arc_auth_results, {
      arc_index => $arc_index,
      authserv  => $authserv,
      results   => \%results,
    };

    dbg("arc: parsed trusted AAR i=%s authserv=%s methods=%s",
        $arc_index, $authserv, join(' ', sort keys %results));
  }

  if (@arc_auth_results) {
    @arc_auth_results = sort { $a->{arc_index} <=> $b->{arc_index} }
                        @arc_auth_results;
    $pms->{arc_auth_results} = \@arc_auth_results;
  }
}

1;

