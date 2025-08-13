#!/usr/bin/perl -T
use utf8;
use open qw( :std :encoding(UTF-8) );
use lib '.'; use lib 't';
use SATest; sa_t_init("util_parse_header_addresses");
use Test::More;

use strict;
require Mail::SpamAssassin::Util;

use constant HAS_IDN => eval { require Net::LibIDN; };
use constant HAS_IDN2 => eval { require Net::LibIDN2; };

plan skip_all => "Net::LibIDN or Net::LibIDN2 is required for this test to pass" unless (HAS_IDN || HAS_IDN2);

my @data = (
    {
        in  => 'companyname <"no reply"@example.com>',
        out => [
            {
                'phrase'  => 'companyname',
                'user'    => '"no reply"',
                'host'    => 'example.com',
                'address' => '"no reply"@example.com',
                'comment' => undef,
                'invalid' => 0
            }
        ],
    },
    {
        in  => 'companyname <no reply@example.com>',
        out => [
            {
                'phrase'  => 'companyname',
                'user'    => 'no reply',
                'host'    => 'example.com',
                'address' => 'no reply@example.com',
                'comment' => undef,
                'invalid' => 1
            }
        ],
    },
    {
        in  => 'Support <support@foo.com_bar.com>',
        out => [
            {
                'phrase'  => 'Support',
                'user'    => 'support',
                'host'    => 'foo.com_bar.com',
                'address' => 'support@foo.com_bar.com',
                'comment' => undef,
                'invalid' => 1
            }
        ],
    },
    {
        in  => 'user@example.みんな',
        out => [
            {
                'phrase'  => undef,
                'user'    => 'user',
                'host'    => 'example.みんな',
                'address' => 'user@example.みんな',
                'comment' => undef,
                'invalid' => 0
            }
        ],
    },
    {
        in  => 'John Doe <jdoe@example.com> (Support Team)',
        out => [
            {
                'phrase'  => 'John Doe',
                'user'    => 'jdoe',
                'host'    => 'example.com',
                'address' => 'jdoe@example.com',
                'comment' => 'Support Team',
                'invalid' => 0
            }
        ],
    },
    {
        in  => 'Alice <alice@example.com>, Bob <bob@example.org>',
        out => [
            {
                'phrase'  => 'Alice',
                'user'    => 'alice',
                'host'    => 'example.com',
                'address' => 'alice@example.com',
                'comment' => undef,
                'invalid' => 0
            },
            {
                'phrase'  => 'Bob',
                'user'    => 'bob',
                'host'    => 'example.org',
                'address' => 'bob@example.org',
                'comment' => undef,
                'invalid' => 0
            }
        ],
    },
    {
        in  => 'Root User <root>',
        out => [
            {
                'phrase'  => 'Root User',
                'user'    => 'root',
                'host'    => undef,
                'address' => 'root',
                'comment' => undef,
                'invalid' => 1
            }
        ],
    },
    {
        in  => 'Invalid <user@domain..com>',
        out => [
            {
                'phrase'  => 'Invalid',
                'user'    => 'user',
                'host'    => 'domain..com',
                'address' => 'user@domain..com',
                'comment' => undef,
                'invalid' => 1
            }
        ],
    },
    {
        in  => '<invalid@address>',
        out => [
            {
                'phrase'  => undef,
                'user'    => 'invalid',
                'host'    => 'address',
                'address' => 'invalid@address',
                'comment' => undef,
                'invalid' => 1
            }
        ],
    },
);

plan tests => scalar @data;

foreach my $test (@data) {
    my $in = $test->{in};
    my $out = $test->{out};

    my @addresses = Mail::SpamAssassin::Util::parse_header_addresses($in);

    is_deeply(\@addresses, $out, "parse_header_addresses('$in')");
}

