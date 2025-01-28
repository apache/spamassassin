#!/usr/bin/perl -T
use strict;
use warnings;
use lib '.'; use lib 't';
use SATest; sa_t_init("parameter_header");
use Test::More;
use Mail::SpamAssassin::Header::ParameterHeader;
use utf8;
my @tests = (
    {
        input    => q|text/plain|,
        expected => {
            value    => 'text/plain',
            parameters => {},
        }
    },
    {
        input    => q|text/plain; charset="utf-8"|,
        expected => {
            value    => 'text/plain',
            parameters => {
                charset => 'utf-8',
            },
        }
    },
    {
        input    => q|text/html; charset=utf-8|,
        expected => {
            value    => 'text/html',
            parameters => {
                charset => 'utf-8',
            },
        }
    },
    {
        input    => q|multipart/mixed; boundary = "--=_Next_Part_24_Nov_2016_08.09.21"|,
        expected => {
            value    => 'multipart/mixed',
            parameters => {
                boundary => '--=_Next_Part_24_Nov_2016_08.09.21',
            },
        }
    },
    {
        input    => q|application/x-zip-compressed; name="D1227348261152122498_202303090926.zip"|,
        expected => {
            value    => 'application/x-zip-compressed',
            parameters => {
                name => 'D1227348261152122498_202303090926.zip',
            },
        }
    },
    {
        input    => q|application/x-stuff; title*='en-us'This%20is%20%2A%2A%2Afun%2A%2A%2A|,
        expected => {
            value    => 'application/x-stuff',
            parameters => {
                title => 'This is ***fun***',
            },
        }
    },
    {
        input    => q|application/x-stuff; title*0*=us-ascii'en'This%20is%20even%20more%20; title*1*=%2A%2A%2Afun%2A%2A%2A%20; title*2="isn't it!"|,
        expected => {
            value    => 'application/x-stuff',
            parameters => {
                title => 'This is even more ***fun*** isn\'t it!',
            },
        }
    },
    {
        input    => q|(comment) text/plain (comment); (comment) charset=ISO-8859-1 (comment)|,
        expected => {
            value    => 'text/plain',
            parameters => {
                charset => 'ISO-8859-1',
            },
        }
    },
    {
        input    => q|(comment \( \\\\) (comment) text/plain; (comment (nested ()comment)another comment)() charset=ISO-8859-1|,
        expected => {
            value    => 'text/plain',
            parameters => {
                charset => 'ISO-8859-1',
            },
        }
    },
    {
        input    => q|text/plain (comment \(not nested ()comment\)\)(nested\(comment())); charset=ISO-8859-1|,
        expected => {
            value    => 'text/plain',
            parameters => {
                charset => 'ISO-8859-1',
            },
        }
    },
    {
        input    => q|application/msword; name="Doc (1).xls" (comment)|,
        expected => {
            value    => 'application/msword',
            parameters => {
                name => 'Doc (1).xls',
            },
        }
    },
    {
        input    => q|attachment;
    filename*0*=utf-8''%E4%BA%94%E9%99%A9%E4%B8%80%E9%87%91%E8%A1%A5%E8%B4%B4.do;
    filename*1=cx|,
        expected => {
            value    => 'attachment',
            parameters => {
                filename => "\x{E4}\x{BA}\x{94}\x{E9}\x{99}\x{A9}\x{E4}\x{B8}\x{80}\x{E9}\x{87}\x{91}\x{E8}\x{A1}\x{A5}\x{E8}\x{B4}\x{B4}.docx",
            },
        }
    },
    {
        input    => qq|attachment; filename*=iso-8859-1''PC-Faktura%20P%E5minnelse.Pdf|,
        expected => {
            value    => 'attachment',
            parameters => {
                filename => "PC-Faktura P\x{C3}\x{A5}minnelse.Pdf",
            },
        }
    },
    {
        input    => q|example.net;
    arc=none (no signatures found);
    dkim=pass (2048-bit rsa key sha256) header.d=google.com header.i=@google.com header.b=ewzn2BS6 header.a=rsa-sha256 header.s=20230601;
    dkim=pass (2048-bit rsa key sha256) header.d=1e100.net header.i=@1e100.net header.b=ewzn2BS6 header.a=rsa-sha256 header.s=20230601;
    dmarc=pass policy.published-domain-policy=reject policy.applied-disposition=none policy.evaluated-disposition=none (p=reject,d=none,d.eval=none) policy.policy-from=p header.from=google.com;
    spf=pass smtp.mailfrom=XXXXXXXXXXXXXX-XXXXX-XXXXXXXXXXX.XXX@data-studio.bounces.google.com smtp.helo=mail-il1-x145.google.com;
    x-tls=pass smtp.version=TLSv1.3 smtp.cipher=TLS_AES_128_GCM_SHA256 smtp.bits=128|,
        expected => {
            value    => 'example.net',
            parameters => {
                arc => 'none',
                dkim => [
                    'pass header.d=google.com header.i=@google.com header.b=ewzn2BS6 header.a=rsa-sha256 header.s=20230601',
                    'pass header.d=1e100.net header.i=@1e100.net header.b=ewzn2BS6 header.a=rsa-sha256 header.s=20230601'
                ],
                dmarc => 'pass policy.published-domain-policy=reject policy.applied-disposition=none policy.evaluated-disposition=none policy.policy-from=p header.from=google.com',
                spf => 'pass smtp.mailfrom=XXXXXXXXXXXXXX-XXXXX-XXXXXXXXXXX.XXX@data-studio.bounces.google.com smtp.helo=mail-il1-x145.google.com',
                'x-tls' => 'pass smtp.version=TLSv1.3 smtp.cipher=TLS_AES_128_GCM_SHA256 smtp.bits=128',
            },
        }
    },
    {
        input    => q|i=1; mx.microsoft.com 1; spf=pass
    smtp.mailfrom=example.org; dmarc=pass action=none
    header.from=example.org; dkim=pass header.d=example.org; arc=none|,
        expected => {
            value    => 'mx.microsoft.com 1',
            parameters => {
                i => '1',
                spf => 'pass smtp.mailfrom=example.org',
                dmarc => 'pass action=none header.from=example.org',
                dkim => 'pass header.d=example.org',
                arc => 'none',
            },
        }
    },
    {
        input    => q|v=1; a=rsa-sha256; c=relaxed/relaxed;
    d=google.com; s=20230601; t=1736148322; x=1736753122; darn=example.com;
    h=to:from:subject:date:message-id:reply-to:mime-version:from:to:cc
     :subject:date:message-id:reply-to;
    bh=VxeNFzGfgtKGc+f/p9MCinYyS5PT9XNqqhJn6CL57cc=;
    b=ewzn2BS6YZcuZQAnyjEQwImwOKee3wFMCh4No2VkOZRVlMas+G5VIGCO6Qb6UAnkHd
     hyQ6RWHxfRWh7r3hPAtYQmhZnVG9kSM4QlbsZlmvlGxf0Z2cJS8nA31l2SoXuy36fn76
     lTh4g/emAy2+emejFf0zlT0mzlTWIwjidtf49Vx3uJRKOpMetzCmkHlaiSqoM0DSdIUh
     0hXLI2rvfLJFIdGGYGGCkMKGtzzTdY8jeP3r0a4FVnDJixJq7bQQ0bOH+HIhf2h7pM8o
     Yu0COOhvqDvMPzfFrxqODtII0yleZu9yt06kXNs5M0uK+Eo0btxi7nibRYyDkR8CdT6d
     dZbA==|,
        expected => {
            value    => '',
            parameters => {
                v => '1',
                a => 'rsa-sha256',
                c => 'relaxed/relaxed',
                d => 'google.com',
                s => '20230601',
                t => '1736148322',
                x => '1736753122',
                darn => 'example.com',
                h => 'to:from:subject:date:message-id:reply-to:mime-version:from:to:cc :subject:date:message-id:reply-to',
                bh => 'VxeNFzGfgtKGc+f/p9MCinYyS5PT9XNqqhJn6CL57cc=',
                b => 'ewzn2BS6YZcuZQAnyjEQwImwOKee3wFMCh4No2VkOZRVlMas+G5VIGCO6Qb6UAnkHd hyQ6RWHxfRWh7r3hPAtYQmhZnVG9kSM4QlbsZlmvlGxf0Z2cJS8nA31l2SoXuy36fn76 lTh4g/emAy2+emejFf0zlT0mzlTWIwjidtf49Vx3uJRKOpMetzCmkHlaiSqoM0DSdIUh 0hXLI2rvfLJFIdGGYGGCkMKGtzzTdY8jeP3r0a4FVnDJixJq7bQQ0bOH+HIhf2h7pM8o Yu0COOhvqDvMPzfFrxqODtII0yleZu9yt06kXNs5M0uK+Eo0btxi7nibRYyDkR8CdT6d dZbA==',
            },
        }
    },
    {
        input    => q|foo.example.net (foobar) 1 (baz);
    dkim (Because I like it) / 1 (One yay) = (wait for it) fail policy (A dot can go here) . (like that) expired (this surprised me) = (as I wasn't expecting it) 1362471462|,
        options => { keep_comments => 1 },
        expected => {
            value    => 'foo.example.net (foobar) 1 (baz)',
            parameters => {
                'dkim / 1' => '(wait for it) fail policy (A dot can go here) . (like that) expired (this surprised me) = (as I wasn\'t expecting it) 1362471462',
            },
        }
    },

    # Now for some non-standard stuff

    {
        input    => q|text/plain;|,
        expected => {
            value    => 'text/plain',
            parameters => {},
        }
    },
    {
        input    => q|; name="Statement_1331801-4229-42.xls"; CHARSET="UTF-8"|,
        expected => {
            value    => '',
            parameters => {
                name => 'Statement_1331801-4229-42.xls',
                charset => 'UTF-8',
            },
        }
    },
    {
        input    => q|application / octet - stream/; name=label.pdf|,
        expected => {
            value    => 'application / octet - stream/',
            parameters => {
                name => 'label.pdf',
            },
        }
    },
    {
        input    => q|image/application/pdf|,
        expected => {
            value    => 'image/application/pdf',
            parameters => {},
        }
    },
    {
        input    => q|text/plain charset=us-ascii|,
        expected => {
            value    => 'text/plain',
            parameters => {
                charset => 'us-ascii',
            },
        }
    },
    {
        input    => q|text/plain; oom*999999999*=us-ascii'en'BIG%20PARAM|,
        expected => {
            value    => 'text/plain',
            parameters => {
                'oom' => 'BIG PARAM',
            },
        }
    },
    {
        input    => q|application/x-stuff; title*3*=us-ascii'en'This%20is%20even%20more%20; title*20*=%2A%2A%2Afun%2A%2A%2A%20; title*100="isn't it!"|,
        expected => {
            value    => 'application/x-stuff',
            parameters => {
                title => q|This is even more ***fun*** isn't it!|,
            },
        }
    },

);

plan tests => scalar @tests;

foreach my $test (@tests) {
    my $input = $test->{input};
    my $expected = $test->{expected};
    my $options = $test->{options} || {};
    my $header = Mail::SpamAssassin::Header::ParameterHeader->new($input, $options);
    my %parameters;
    foreach ($header->parameters) {
        my @values = $header->parameter($_);
        $parameters{$_} = @values > 1 ? \@values : $values[0];
    }
    my $result = {
        value => $header->value,
        parameters => \%parameters,
    };
    is_deeply($result, $expected, "ParameterHeader: $input");
}
