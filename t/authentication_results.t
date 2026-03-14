#!/usr/bin/perl -T
use strict;
use warnings;
use lib '.'; use lib 't';
use SATest; sa_t_init("authentication_results");
use Test::More;
use Mail::SpamAssassin::Header::AuthenticationResults;

my @tests = (
    {
        name     => 'basic single method',
        input    => 'example.com; spf=pass smtp.mailfrom=user@example.com',
        expected => {
            authserv_id => 'example.com',
            version     => 1,
            methods     => {
                spf => [
                    {
                        result     => 'pass',
                        reason     => '',
                        properties => { smtp => { mailfrom => 'user@example.com' } },
                    },
                ],
            },
        },
    },
    {
        name     => 'authserv-id with version',
        input    => 'example.com 1; spf=pass smtp.mailfrom=x',
        expected => {
            authserv_id => 'example.com',
            version     => 1,
            methods     => {
                spf => [
                    {
                        result     => 'pass',
                        reason     => '',
                        properties => { smtp => { mailfrom => 'x' } },
                    },
                ],
            },
        },
    },
    {
        name     => 'multi-method',
        input    => 'example.com; spf=pass smtp.mailfrom=x; dkim=pass header.d=y; dmarc=fail header.from=z',
        expected => {
            authserv_id => 'example.com',
            version     => 1,
            methods     => {
                spf => [
                    {
                        result     => 'pass',
                        reason     => '',
                        properties => { smtp => { mailfrom => 'x' } },
                    },
                ],
                dkim => [
                    {
                        result     => 'pass',
                        reason     => '',
                        properties => { header => { d => 'y' } },
                    },
                ],
                dmarc => [
                    {
                        result     => 'fail',
                        reason     => '',
                        properties => { header => { from => 'z' } },
                    },
                ],
            },
        },
    },
    {
        name     => 'multiple same-method',
        input    => 'example.com; dkim=pass header.d=a; dkim=fail header.d=b',
        expected => {
            authserv_id => 'example.com',
            version     => 1,
            methods     => {
                dkim => [
                    {
                        result     => 'pass',
                        reason     => '',
                        properties => { header => { d => 'a' } },
                    },
                    {
                        result     => 'fail',
                        reason     => '',
                        properties => { header => { d => 'b' } },
                    },
                ],
            },
        },
    },
    {
        name     => 'multiple properties',
        input    => 'example.com; dkim=pass header.d=example.com header.i=@example.com header.b=abcdef header.a=rsa-sha256 header.s=selector1',
        expected => {
            authserv_id => 'example.com',
            version     => 1,
            methods     => {
                dkim => [
                    {
                        result     => 'pass',
                        reason     => '',
                        properties => { header => { d => 'example.com', i => '@example.com', b => 'abcdef', a => 'rsa-sha256', s => 'selector1' } },
                    },
                ],
            },
        },
    },
    {
        name     => 'quoted value',
        input    => 'example.com; dkim=pass header.i="user@example.com"',
        expected => {
            authserv_id => 'example.com',
            version     => 1,
            methods     => {
                dkim => [
                    {
                        result     => 'pass',
                        reason     => '',
                        properties => { header => { i => 'user@example.com' } },
                    },
                ],
            },
        },
    },
    {
        name     => 'quoted value with equals (SRS address)',
        input    => 'example.com; spf=pass smtp.mailfrom="SRS0+HHH=orig=user@fwd.com"',
        expected => {
            authserv_id => 'example.com',
            version     => 1,
            methods     => {
                spf => [
                    {
                        result     => 'pass',
                        reason     => '',
                        properties => { smtp => { mailfrom => 'SRS0+HHH=orig=user@fwd.com' } },
                    },
                ],
            },
        },
    },
    {
        name     => 'comments (CFWS)',
        input    => 'example.com; dkim=pass (good sig) header.d=x; spf=pass (authorized) smtp.mailfrom=y',
        expected => {
            authserv_id => 'example.com',
            version     => 1,
            methods     => {
                dkim => [
                    {
                        result     => 'pass',
                        reason     => '',
                        properties => { header => { d => 'x' } },
                    },
                ],
                spf => [
                    {
                        result     => 'pass',
                        reason     => '',
                        properties => { smtp => { mailfrom => 'y' } },
                    },
                ],
            },
        },
    },
    {
        name     => 'reason field',
        input    => 'example.com; spf=fail reason="not authorized" smtp.mailfrom=x',
        expected => {
            authserv_id => 'example.com',
            version     => 1,
            methods     => {
                spf => [
                    {
                        result     => 'fail',
                        reason     => 'not authorized',
                        properties => { smtp => { mailfrom => 'x' } },
                    },
                ],
            },
        },
    },
    {
        name     => 'action field (consumed, not stored)',
        input    => 'example.com; dmarc=pass action=none header.from=x',
        expected => {
            authserv_id => 'example.com',
            version     => 1,
            methods     => {
                dmarc => [
                    {
                        result     => 'pass',
                        reason     => '',
                        properties => { header => { from => 'x' } },
                    },
                ],
            },
        },
    },
    {
        name     => 'method version (dkim/1)',
        input    => 'example.com; dkim/1=pass header.d=x',
        expected => {
            authserv_id => 'example.com',
            version     => 1,
            methods     => {
                dkim => [
                    {
                        result     => 'pass',
                        reason     => '',
                        properties => { header => { d => 'x' } },
                    },
                ],
            },
        },
    },
    {
        name     => 'none - empty methods',
        input    => 'example.com; none',
        expected => {
            authserv_id => 'example.com',
            version     => 1,
            methods     => {},
        },
    },
    {
        name     => 'unknown methods preserved',
        input    => 'example.com; x-tls=pass smtp.version=TLSv1.3 smtp.cipher=TLS_AES_128_GCM_SHA256',
        expected => {
            authserv_id => 'example.com',
            version     => 1,
            methods     => {
                'x-tls' => [
                    {
                        result     => 'pass',
                        reason     => '',
                        properties => { smtp => { version => 'TLSv1.3', cipher => 'TLS_AES_128_GCM_SHA256' } },
                    },
                ],
            },
        },
    },
    {
        name     => 'extended properties preserved',
        input    => 'example.com; dmarc=pass policy.published-domain-policy=reject policy.applied-disposition=none header.from=x',
        expected => {
            authserv_id => 'example.com',
            version     => 1,
            methods     => {
                dmarc => [
                    {
                        result     => 'pass',
                        reason     => '',
                        properties => {
                            policy => { 'published-domain-policy' => 'reject', 'applied-disposition' => 'none' },
                            header => { from => 'x' },
                        },
                    },
                ],
            },
        },
    },
    {
        name     => 'header from Mail::Milter::Authentication',
        input    => 'mail.example.net;
    arc=pass smtp.remote-ip=2a01:0111:f403:c111:0000:0000:0000:0009;
    dkim=pass header.d=example.org header.i=@example.org header.b=QruneRbB header.a=rsa-sha256 header.s=selector1;
    dmarc=pass policy.published-domain-policy=reject policy.applied-disposition=none policy.evaluated-disposition=none policy.policy-from=p header.from=example.org;
    spf=pass smtp.mailfrom=Andrew.Madrigal@example.org smtp.helo=DM5PR21CU001.outbound.protection.outlook.com;
    x-tls=pass smtp.version=TLSv1.3 smtp.cipher=TLS_AES_256_GCM_SHA384 smtp.bits=256',
        expected => {
            authserv_id => 'mail.example.net',
            version     => 1,
            methods     => {
                arc => [
                    {
                        result     => 'pass',
                        reason     => '',
                        properties => { smtp => { 'remote-ip' => '2a01:0111:f403:c111:0000:0000:0000:0009' } },
                    },
                ],
                dkim => [
                    {
                        result     => 'pass',
                        reason     => '',
                        properties => { header => { d => 'example.org', i => '@example.org', b => 'QruneRbB', a => 'rsa-sha256', s => 'selector1' } },
                    },
                ],
                dmarc => [
                    {
                        result     => 'pass',
                        reason     => '',
                        properties => {
                            policy => { 'published-domain-policy' => 'reject', 'applied-disposition' => 'none', 'evaluated-disposition' => 'none', 'policy-from' => 'p' },
                            header => { from => 'example.org' },
                        },
                    },
                ],
                spf => [
                    {
                        result     => 'pass',
                        reason     => '',
                        properties => { smtp => { mailfrom => 'Andrew.Madrigal@example.org', helo => 'DM5PR21CU001.outbound.protection.outlook.com' } },
                    },
                ],
                'x-tls' => [
                    {
                        result     => 'pass',
                        reason     => '',
                        properties => { smtp => { version => 'TLSv1.3', cipher => 'TLS_AES_256_GCM_SHA384', bits => '256' } },
                    },
                ],
            },
        },
    },
    {
        name     => 'quoted with escaped quotes',
        input    => 'example.com; dkim=pass header.i=" foo \"bar\"@example.com"',
        expected => {
            authserv_id => 'example.com',
            version     => 1,
            methods     => {
                dkim => [
                    {
                        result     => 'pass',
                        reason     => '',
                        properties => { header => { i => ' foo \"bar\"@example.com' } },
                    },
                ],
            },
        },
    },
    {
        name     => 'method version with spaces (dkim / 1)',
        input    => 'example.com; dkim / 1=pass header.d=x',
        expected => {
            authserv_id => 'example.com',
            version     => 1,
            methods     => {
                dkim => [
                    {
                        result     => 'pass',
                        reason     => '',
                        properties => { header => { d => 'x' } },
                    },
                ],
            },
        },
    },
);

plan tests => scalar @tests;

foreach my $test (@tests) {
    my $ar = Mail::SpamAssassin::Header::AuthenticationResults->new($test->{input});
    my %methods;
    foreach my $method ($ar->methods()) {
        $methods{$method} = [ $ar->method($method) ];
    }
    my $result = {
        authserv_id => $ar->authserv_id(),
        version     => $ar->version(),
        methods     => \%methods,
    };
    is_deeply($result, $test->{expected}, $test->{name});
}
