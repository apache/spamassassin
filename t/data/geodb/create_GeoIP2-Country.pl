#!/usr/bin/perl

use MaxMind::DB::Writer::Tree;

my %types = (
  code => 'utf8_string',
  continent => 'map',
  country => 'map',
  en => 'utf8_string',
  geoname_id => 'uint32',
  iso_code => 'utf8_string',
  names => 'map',
  registered_country => 'map',
);

my $tree = MaxMind::DB::Writer::Tree->new(
  database_type => 'GeoIP2-Country',
  description => { en => 'SpamAssassin test data' },
  ip_version => 6,
  record_size => 28,
  map_key_type_callback => sub { $types{ $_[0] } },
);

$tree->insert_network(
    '8.8.8.8/32' => {
        'continent' => {
            'code' => 'NA',
            'geoname_id' => 6255149,
            'names' => {
                'en' => 'North America',
            },
        },
        'country' => {
            'iso_code' => 'US',
            'geoname_id' => 6252001,
            'names' => {
                'en' => 'United States',
            },
        },
        'registered_country' => {
            'iso_code' => 'US',
            'geoname_id' => 6252001,
            'names' => {
                'en' => 'United States',
            },
        },
    },
);
$tree->insert_network(
    '2001:4860:4860::8888/128' => {
        'continent' => {
            'code' => 'NA',
            'geoname_id' => 6255149,
            'names' => {
                'en' => 'North America',
            },
        },
        'country' => {
            'iso_code' => 'US',
            'geoname_id' => 6252001,
            'names' => {
                'en' => 'United States',
            },
        },
        'registered_country' => {
            'iso_code' => 'US',
            'geoname_id' => 6252001,
            'names' => {
                'en' => 'United States',
            },
        },
    },
);

open my $fh, '>:raw', 'GeoIP2-Country.mmdb';
$tree->write_tree($fh);
close $fh;

