#!/usr/bin/perl

use MaxMind::DB::Writer::Tree;

my %types = (
  isp => 'utf8_string',
  autonomous_system_organization => 'utf8_string',
  organization => 'utf8_string',
  autonomous_system_number => 'uint32',
);

my $tree = MaxMind::DB::Writer::Tree->new(
  database_type => 'GeoIP2-ISP',
  description => { en => 'SpamAssassin test data' },
  ip_version => 6,
  record_size => 28,
  map_key_type_callback => sub { $types{ $_[0] } },
);

$tree->insert_network(
    '8.8.8.8/32' => {
        'isp' => 'Level 3 Communications',
        'autonomous_system_organization' => 'GOOGLE - Google LLC, US',
        'organization' => 'Google',
        'autonomous_system_number' => 15169,
    },
);
$tree->insert_network(
    '2001:4860:4860::8888/128' => {
        'isp' => 'Level 3 Communications',
        'autonomous_system_organization' => 'GOOGLE - Google LLC, US',
        'organization' => 'Google',
        'autonomous_system_number' => 15169,
    },
);

open my $fh, '>:raw', 'GeoIP2-ISP.mmdb';
$tree->write_tree($fh);
close $fh;

