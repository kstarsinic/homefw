package Net::Inspect;

# XXX This is built against a custom IO::Interface with USE_GETIFADDRS and HAVE_SOCKADDR_DL_STRUCT defined

use strict;
use warnings;

use Net::Pcap;
use IO::Interface           qw(:flags);
use IO::Interface::Simple;
use Regexp::IPv6            qw($IPv6_re);
use Regexp::Common          qw(net);
use Socket                  qw(inet_ntoa);

# NetPacket:
# ARP
# Ethernet
# ICMP
# IGMP
# IP
# IPX
# TCP
# UDP
# USBMon
use NetPacket::Ethernet     qw(:types);
use NetPacket::IP           qw(:protos);
use NetPacket::TCP;
use NetPacket::UDP;

use Data::Dumper;
$Data::Dumper::Indent = 0;
$Data::Dumper::Terse  = 1;


# Constant            Mac       IO::Interface   method
# IFF_UP              0x1       y
#.IFF_BROADCAST       0x2       y               is_broadcast
# IFF_DEBUG           0x4       y
#.IFF_LOOPBACK        0x8       y               is_loopback
#.IFF_POINTOPOINT     0x10      y               is_pt2pt
#.IFF_NOTRAILERS      0x20      y               is_notrailers
#.IFF_RUNNING         0x40      y               is_running
#.IFF_NOARP           0x80      y               is_noarp
#.IFF_PROMISC         0x100     y               is_promiscuous
# IFF_ALLMULTI        0x200     y
# IFF_OACTIVE         0x400       
# IFF_SIMPLEX         0x800       
# IFF_LINK0           0x1000        
# IFF_LINK1           0x2000        
# IFF_LINK2           0x4000        
#.IFF_MULTICAST	      0x8000	  y               is_multicast

# IFF_ALTPHYS         IFF_LINK2   
# IFF_AUTOMEDIA       -         y
# IFF_MASTER          -         y
# IFF_PORTSEL         -         y
# IFF_SLAVE           -         y

my $Format  = "    %-12s %-14s %-14s\n";

my %T2N = (
  DLT_EN10MB()      => {
    ETH_TYPE_IP()         => 'IP',
    ETH_TYPE_ARP()        => 'ARP',
    ETH_TYPE_APPLETALK()  => 'APPLETALK',
    ETH_TYPE_SNMP()       => 'SNMP',
    ETH_TYPE_IPv6()       => 'IPv6',
    ETH_TYPE_PPP()        => 'PPP',
  },
  ETH_TYPE_IP()     => {
  },
);
my %Boring  = (
  DLT_EN10MB()      => {
    _frame      => 1,
    _parent     => 1,
    data        => 1,
    dest_mac    => 1,
    src_mac     => 1,
    type        => 1,
  },

  ETH_TYPE_IP()     => {
    _frame      => 1,
    _parent     => 1,
    cksum       => 1,
    data        => 1,
    dest_ip     => 1,
    flags       => 1,
    foffset     => 1,
    hlen        => 1,
    id          => 1,
    len         => 1,
    options     => 1,
    proto       => 1,
    src_ip      => 1,
    tos         => 1,
    ttl         => 1,
    ver         => 1,
  },

  IP_PROTO_TCP()    => {
    _frame      => 1,
    _parent     => 1,
    acknum      => 1,
    cksum       => 1,
    data        => 1,
    dest_port   => 1,
    flags       => 1,
    hlen        => 1,
    options     => 1,
    reserved    => 1,
    seqnum      => 1,
    src_port    => 1,
    urg         => 1,
    winsize     => 1,
  },

  IP_PROTO_UDP()    => {
    _frame      => 1,
    _parent     => 1,
    cksum       => 1,
    data        => 1,
    dest_port   => 1,
    len         => 1,
    src_port    => 1,
  },
);


sub new {
  my ($class, %etc) = @_;
  my $self          = bless {
    interfaces      => undef,
    if              => { },
    err             => undef,
    %etc
  }, $class;

  return $self;
}


sub interfaces {
  my ($self, %which)  = @_;

  if (not $$self{interfaces}) {
    $$self{interfaces}  = [ pcap_findalldevs(\my %devinfo, \$$self{err}) ];

    foreach my $name (@{ $$self{interfaces} }) {
      my $if = IO::Interface::Simple->new($name);

      #   Missing IO::Interface flags from old Makefile.PL:
      #     -DUSE_GETIFADDRS            needs /usr/include/ifaddrs.h!
      #     -DHAVE_SOCKADDR_DL_STRUCT   needs /usr/include/net/if.dl.h!
      $$self{if}{$name} = {
        # description => $devinfo{$name}, # boring: always "Loopback device" or "No description available" for me.
        index       => $if->index,

        address     => $if->address,
        broadcast   => $if->broadcast,
        netmask     => $if->netmask,
        dstaddr     => $if->dstaddr,
        hwaddr      => $if->hwaddr,

        mtu         => $if->mtu,
        metric      => $if->metric,
        flags       => sprintf("0x%04x", ($if->flags & 0xffff)),
      };

      # Flags:
      $$self{if}{$name}{is_up}        = !!($if->flags & IFF_UP);
      $$self{if}{$name}{is_broadcast} = !!($if->is_broadcast);
      $$self{if}{$name}{debug}        = !!($if->flags & IFF_DEBUG);
      $$self{if}{$name}{loopback}     = !!($if->is_loopback);
      $$self{if}{$name}{pt2pt}        = !!($if->is_pt2pt);
      $$self{if}{$name}{notrailers}   = !!($if->is_notrailers);
      $$self{if}{$name}{running}      = !!($if->is_running);
      $$self{if}{$name}{noarp}        = !!($if->is_noarp);
      $$self{if}{$name}{promisc}      = !!($if->is_promiscuous);
      $$self{if}{$name}{allmulti}     = !!($if->flags & 0x0200);
      $$self{if}{$name}{active}       = !!($if->flags & 0x0400);
      $$self{if}{$name}{simplex}      = !!($if->flags & 0x0800);
      $$self{if}{$name}{link0}        = !!($if->flags & 0x1000);
      $$self{if}{$name}{link1}        = !!($if->flags & 0x2000);
      $$self{if}{$name}{link2}        = !!($if->flags & 0x4000);
      $$self{if}{$name}{multicast}    = !!($if->is_multicast);

      # This fetches the same values as $if->address and $if->netmask.
      # if (pcap_lookupnet($name, \my $net, \my $mask, \$$self{err}) < 0) {
      #   $$self{if}{$name}{_net} = $$self{err};
      # } else {
      #   $$self{if}{$name}{net}  = _dotquad($net);
      #   $$self{if}{$name}{mask} = _dotquad($mask);
      # }
    }

    @{ $$self{interfaces} } = sort { $$self{if}{$a}{index} <=> $$self{if}{$b}{index} } @{ $$self{interfaces} };
  }

  grep {
    not %which or
    $which{_up} && $$self{if}{$_}{is_up} && $$self{if}{$_}{address}
  } @{ $$self{interfaces} };
}


sub trace {
  my ($self)   = @_;
  my %e2n;
  my @pcap;

  foreach my $name ($self->interfaces(_up => 1)) {
    $e2n{$$self{if}{$name}{hwaddr}} = $name if $$self{if}{$name}{hwaddr};

    $$self{err} = undef;
    my $pcap = pcap_open_live($name, 4096, 1, 100, \$$self{err});

    if ($$self{err}) {
      warn "pcap_open_live($name): $$self{err}";
    } else {
      my $dl    = pcap_datalink($pcap);
      my $name  = pcap_datalink_val_to_name($dl);
      my $desc  = pcap_datalink_val_to_description($dl);
      printf "%-8s %-8s %s\n", $dl, $name, $desc;
      push @pcap, [ $name, $pcap, $dl ];
    }
  }

  my %stats = (total => 0);
  foreach my $i (0 .. 1000) {
    foreach my $l (@pcap) {
      my ($name, $pcap, $dl)  = @$l;
      my $raw                 = pcap_next($pcap, \my %header);

      if (defined $raw) {
        printf "%4d %-8s packet %-8s header %s\n", $i, $name, '', Dumper(\%header);

        if ($dl == DLT_EN10MB) {
          my $np = NetPacket::Ethernet->decode($raw);
          my $conn = "$$np{src_mac} -> $$np{dest_mac}";

          my %local;
          foreach my $key (qw(src_mac dest_mac)) {
            my $mac = $$np{$key};

            $$np{$key} = join ':', $$np{$key} =~ /(..)/g;
            ++$local{$key} if $e2n{$$np{$key}};
            $$np{$key} = $e2n{$$np{$key}} if $e2n{$$np{$key}};
          }

          if    (not %local)                            { ++$stats{dir_other};    ++$stats{conn_other}{$conn}; }
          elsif ($local{src_mac} and $local{dest_mac})  { ++$stats{dir_internal}; ++$stats{conn_internal}{$conn}; }
          elsif ($local{src_mac})                       { ++$stats{dir_out};      ++$stats{conn_out}{$conn}; }
          elsif ($local{dest_mac})                      { ++$stats{dir_in};       ++$stats{conn_in}{$conn}; }
          else                                          { die Dumper $np, \%local; }

          printf $Format, 'Enet', $$np{src_mac}, $$np{dest_mac};

          ++$stats{$$np{src_mac}}{$$np{dest_mac}};
          ++$stats{$$np{dest_mac}}{$$np{src_mac}};

          foreach my $key (sort grep { not $Boring{DLT_EN10MB()}{$_} } keys %$np) {
            printf $Format, 'Enet', $key, $$np{$key};
          }

          if (_unpack($$np{type}, $$np{data})) {
            ++$stats{total};
            last if $stats{total} > 10;
          }
        }

        print "\n";
      }
    }

    last if $stats{total} > 10;
  }

  return %stats;
}


sub _unpack {
  my ($type, $raw)  = @_;

  if ($type eq ETH_TYPE_IP()) {
    return _unpack_ip($raw);

    return;
  }
}


sub _unpack_ip {
  my ($raw) = @_;
  my $np    = NetPacket::IP->decode($raw);

  printf $Format, 'IP', $$np{src_ip}, $$np{dest_ip};
  foreach my $key (sort grep { not $Boring{ETH_TYPE_IP()}{$_} } keys %$np) {
    printf $Format, 'IP', $key, $$np{$key} // '<undef>';
  }

  if ($$np{proto} == IP_PROTO_IP) {
    print "IP!\n";
  } elsif ($$np{proto} == IP_PROTO_ICMP) {
    print "ICMP!\n";
  } elsif ($$np{proto} == IP_PROTO_IGMP) {
    print "IGMP!\n";
  } elsif ($$np{proto} == IP_PROTO_IPIP) {
    print "IPIP!\n";
  } elsif ($$np{proto} == IP_PROTO_TCP) {
    _unpack_tcp($$np{data});
  } elsif ($$np{proto} == IP_PROTO_UDP) {
    _unpack_udp($$np{data});
  } else {
    printf "huh? %s\n", Dumper($np);
  }
  return 1;
}


sub _unpack_udp {
  my ($raw) = @_;
  my $np    = NetPacket::UDP->decode($raw);

  printf $Format, 'UDP', $$np{src_port}, $$np{dest_port};
  foreach my $key (sort grep { not $Boring{IP_PROTO_UDP()}{$_} } keys %$np) {
    printf $Format, 'UDP', $key, $$np{$key} // '<undef>';
  }
}


sub _unpack_tcp {
  my ($raw) = @_;
  my $np    = NetPacket::TCP->decode($raw);

  printf $Format, 'TCP', $$np{src_port}, $$np{dest_port};
  foreach my $key (sort grep { not $Boring{IP_PROTO_TCP()}{$_} } keys %$np) {
    printf $Format, 'TCP', $key, $$np{$key} // '<undef>';
  }
}


# inet_ntoa(pack("I", $n);
sub _dotquad {  # Cribbed from eg/pcapdump's run(), but corrected to network byte order
  my ($n)  = @_;

  return inet_ntoa(pack("N", $n));
}


1;

