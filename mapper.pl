#!/usr/bin/env perl

use strict;
use warnings;

use lib 'lib';

use Net::Inspect;
my $Inspect = Net::Inspect->new;

use Data::Dumper;

use Getopt::Long;
my %Opt = ();
GetOptions(\%Opt,
  'trace',
);

foreach my $name ($Inspect->interfaces(_up => 1)) {
  my $if = $$Inspect{if}{$name};

  printf "%2d %-14s %s\n", $$if{index}, $name, $$if{is_up} ? 'UP' : 'DOWN';
  foreach my $key (sort grep { not /^(index|is_up)$/ and $$if{$_} } keys %$if) {
    printf "  %-18s %s\n", $key, $$if{$key};
  }
}

if ($Opt{trace}) {
  my %stats = $Inspect->trace;
  print "Trace statistics:\n";
  foreach my $key (sort keys %stats) {
    if (ref $stats{$key}) {
      foreach my $k2 (sort keys %{ $stats{$key} }) {
        printf "  %-17s %-17s %4d\n", $key, $k2, $stats{$key}{$k2};
      }
    } else {
      printf "  %-17s %-17s %4d\n", $key, '', $stats{$key};
    }
  }
}

