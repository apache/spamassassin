#!/usr/bin/perl

use MaxMind::DB::Writer::Tree;

my %types = (
  accuracy_radius => 'uint32',
  autonomous_system_number => 'uint32',
  is_in_european_union => 'uint32',
  autonomous_system_organization => 'utf8_string',
  city => 'map',
  continent => 'map',
  country => 'map',
  en => 'utf8_string',
  geoname_id => 'uint32',
  iso_code => 'utf8_string',
  code => 'utf8_string',
  isp => 'utf8_string',
  latitude => 'double',
  location => 'map',
  longitude => 'double',
  names => 'map',
  organization => 'utf8_string',
  registered_country => 'map',
  time_zone => 'utf8_string',
  subdivisions => ['array', 'map'],
);

my $tree = MaxMind::DB::Writer::Tree->new(
  database_type => 'GeoIP2-City',
  description => { en => 'SpamAssassin test data' },
  ip_version => 6,
  record_size => 28,
  map_key_type_callback => sub { $types{ $_[0] } },
);

$tree->insert_network(
    '8.8.8.8/32' => {
          'country' => {
                         'iso_code' => 'US',
                         'is_in_european_union' => 0,
                         'names' => {
                                      'en' => 'United States',
                                    },
                         'geoname_id' => 6252001
                       },
          'continent' => {
                           'names' => {
                                        'en' => 'North America',
                                      },
                           'geoname_id' => 6255149,
                           'code' => 'NA'
                         },
          'subdivisions' => [
                              {
                                'names' => {
                                             'en' => 'United States',
                                           },
                                'geoname_id' => 6269131,
                                'iso_code' => 'USA'
                              }
                            ],
          'city' => {
                      'names' => {
                                   'en' => 'New York',
                                 },
                      'geoname_id' => 5128581
                    },
          'registered_country' => {
                                    'iso_code' => 'US',
                                    'geoname_id' => 6252001,
                                    'names' => {
                                                 'en' => 'United States'
                                               }
                                  },
          'location' => {
                          'latitude' => '43.0003',
                          'longitude' => '-75.4999',
                          'time_zone' => 'America/New_York',
                          'accuracy_radius' => 10
                        }
    },
);
$tree->insert_network(
    '2001:4860:4860::8888/128' => {
          'country' => {
                         'iso_code' => 'US',
                         'is_in_european_union' => 0,
                         'names' => {
                                      'en' => 'United States',
                                    },
                         'geoname_id' => 6252001
                       },
          'continent' => {
                           'names' => {
                                        'en' => 'North America',
                                      },
                           'geoname_id' => 6255149,
                           'code' => 'NA'
                         },
          'subdivisions' => [
                              {
                                'names' => {
                                             'en' => 'United States',
                                           },
                                'geoname_id' => 6269131,
                                'iso_code' => 'USA'
                              }
                            ],
          'city' => {
                      'names' => {
                                   'en' => 'New York',
                                 },
                      'geoname_id' => 5128581
                    },
          'registered_country' => {
                                    'iso_code' => 'US',
                                    'geoname_id' => 6252001,
                                    'names' => {
                                                 'en' => 'United States'
                                               }
                                  },
          'location' => {
                          'latitude' => '43.0003',
                          'longitude' => '-75.4999',
                          'time_zone' => 'America/New_York',
                          'accuracy_radius' => 10
                        }
    },
);

open my $fh, '>:raw', 'GeoIP2-City.mmdb';
$tree->write_tree($fh);
close $fh;

