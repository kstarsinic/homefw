#!/usr/bin/env perl

use strict;
use warnings;

use Net::Pcap;
use Data::Dumper;

my (%devinfo, $err);

foreach my $dev (pcap_findalldevs(\%devinfo, \$err)) {
  if (defined $err) {
    printf "dev %-20s error %s\n", $dev, $err;
  } else {
    printf "dev %-20s %s %s\n", $dev, $devinfo{$dev}, Dumper(\%devinfo);

    my $pcap = pcap_open_live($dev, 4096, 1, 5000, \$err);

    if (defined $err) {
      printf "err %s\n", $err;
    } else {
      printf "pcap %s\n", $pcap;
      my %header;
      my $packet = pcap_next($pcap, \%header);
      if (defined $packet) {
        printf "packet %s header %s\n", 'ok', Dumper(\%header);
      }
    }

    printf "pcap %s\n", Dumper($pcap);
    pcap_close($pcap) if $pcap;
  }
}

