# Mail::MTAMark::Query
# Copyright 2005 Malte S. Stretz <http://msquadrat.de>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

package Mail::MTAMark::Query;

=head1 NAME

Mail::MTAMark::Query - validating MTAs via RDNS

=head1 SYNOPSIS

  my $ip = join '.', unpack 'C4', ( gethostbyname("www.example.net") )[4];
  my $query = Mail::MTAMark::Query->new(ip => $ip);
  my $result = $query->result();

  if ($result eq 'pass') {
    print "The host at $ip is allowed to act as a MTA.\n";
  }
  elsif ($result eq 'fail') {
    print "The host at $ip must not act as a MTA.\n";
  }
  elsif ($result eq 'unknown') {
    print "There's no MTAMark information about host $ip.\n";
  }
  else {
    print "An error occurred while querying MTAMark information about host $ip.\n";
  }

=head1 DESCRIPTION

MTAMark is a very simple mail server authentication scheme which relies on
information published in Reverse DNS.  For each IP address a flag can be
set which either allows or forbids that host to act as a MTA. Given an IP 
address, Mail::MTAMark::Query determines whether that host is a valid MTA
or not.

The simplest way to use this module is calling the C<result> method after
creating the object.  It will try to fetch the MTAMark and all additional
information about the given IP address.  You can modify the behaviour
via some L<constructor|/CONSTRUCTOR> switches.

A more sophisticated way of using this module is to call some or all the 
steps performed by C<result> manually.  That might be useful if you want
to do the DNS queries in the background with C<Net::DNS::Resolver::bgsend>.

=cut

use 5.006;
use strict;
use warnings;

use Net::IP qw();
use Net::DNS qw();

use vars qw($VERSION);

$VERSION = '0.001';

=head1 CONSTRUCTOR

=over

=item new

Creates a new Mail::SPF::Query object.  Several attribute-value pairs modify
the behaviour of the object, the only required one is some kind of C<ip>.

The constructor will return at most two values.  The first one is either an
Mail::MTAMArk::Query object or undef if anything failed.  In the latter case,
a second parameter is returned which contains the error string.

  my ($q, $e) = Mail::MTAMark::Query->new(ip => "10.11.12.13", arpa => "local");
  unless (defined $q) {
    die "Construction of Mail::MTAMArk::Query object failed: $e";
  }

Available options:

=over

=cut

sub new {
  my $class = shift;
  $class = ref($class) || $class;
  
  my %self = (
=pod
  
=item ip

The IP to be queried.  The value must be a valid IPv4 or IPv6 address; the
IP version is automagically determined and the correct zone (in-addr.arpa
vs. ip6.arpa) will be used.

=cut
    ip   => undef,
=pod

=item ipv4/ipv6

These options are an alternative to C<ip>.  They force force an IP version
and the value must be a valid IP of that version.  It is also possible to
specify both an IPv4 and IPv6 address.

In the latter case, first the IPv4 one is queried and if there isn't any 
information available, the query will continue with the IPv6 one.  The 
order in which the addresses are queried might change one day.

=cut
    ipv4 => undef,
    ipv6 => undef,

=pod

=item query_rp

The MTAMark specification suggests that the RP (Responsible Person) 
information is retrieved for any MTAMark enabled IP.  If such information
is available, it will be returned by the C<result> method.  This boolean
value enables or disables this query.  The default is enabled which might
change at some point in the future.

=cut
    query_rp => 1,
    
=pod

=item resolver

Per default, the object will internally create an L<Net::DNS::Resolver> 
object to retrieve the information from DNS.  Alternatively it will use 
the object specified by this option.  It doesn't have to be a Net::DNS 
object, it just needs an C<send> method which accepts exactly the same
parameters as C<Net::DNS::Resolver::send> does.

This can be useful if you want to reuse an existing Resolver object or
need to do some additional caching/packet mangling or just want to modify
the default timeouts.

=cut
    resolver => undef,
=pod

=item arpa

MTAMark informations are queried either from the in-addr.arpa (IPv4) or 
the ip6.arpa (IPv6) zone.  With this option it is possible to replace the
"arpa" part, very useful for testing and debugging.  See also 
L<"THE PROTOCOL">.

=cut
    arpa => 'arpa',
    
    QUEUE => [],
    RP    => 0,
    
    RESULT  => 'none',
    MAILBOX => '',

    ERROR => 'Oops',
    NOISY_NET_IP => $Net::IP::VERSION == 1.22,
  );
  my %opts = ( @_ );
  foreach my $opt (keys %opts) {
    $self{$opt} = $opts{$opt} if exists $self{$opt};
  }

  my @queue = ('');
  if (defined $self{ip}) {
    my $ips = delete $self{ip};
    my $ipo = Net::IP->new($ips)
                or return (undef, "Invalid ip ($ips): " . Net::IP::Error());
    my $ipv = $ipo->version()
                or return (undef, "Invalid ip ($ips): " . $ipo->error());
    my $ipk = 'ipv' . $ipv;
    $self{$ipk} = $ipo;
    $queue[0]   = $ipk;
  }
  unless ($self{ipv4} || $self{ipv6}) {
    return (undef, "IP required");
  }
  
  foreach my $ipv (qw(4 6)) {
    my $ipk = 'ipv' . $ipv;
    my $ips = $self{$ipk};
    next if not defined $ips or ref $ips;
    $self{$ipk} = Net::IP->new($ips, $ipv)
                    or return (undef, "Invalid $ipk ($ips): " . Net::IP::Error());
    push(@queue, $ipk) unless $queue[0] eq $ipk;
  }
  
  shift(@queue) unless $queue[0];
  $self{'QUEUE'} = [ @queue ];
  
  return bless({ %self }, $class);
}

=back

=back

=cut

=head1 METHODS

=over

=cut

=pod

=item result



=cut

sub result {
  my ($self) = @_;
  
  return $self->{RESULT} unless $self->{RESULT} eq q(none);
  return $self->{RESULT} unless @{$self->{QUEUE}};
  
  my $res;
  do {
    $res = $self->process_packet();
    return q(error) unless defined $res;
  }
  while ($res);
  
  return ($self->{RESULT});
}


=pod

=item error

Returns the error string which was set by the last failed method.

=cut

sub error {
  my $self = shift;
  return $self->{ERROR};
}

sub _e {
  my $self = shift;
  $self->{ERROR} = $_[0];
  return undef;
}

=pod

=item create_packet

This is a factory for the next L<Net::DNS::Packet> in queue.  It returns 
either a new Packet object or undef if an error occured.  The error string
can be retrieved with the C<error> method.

See also L<"THE FLOW">.

=cut

sub create_packet {
  my $self = shift;
  
  my $ipk = ${$self->{'QUEUE'}}[0]
              or return $self->_e("No requests in queue");
  
  my $domain = $self->_reverse_ip($ipk) or return undef;
  $domain = join('.' => qw(_send _smtp _srv), $domain);
  $domain =~ s/arpa\.?$/$self->{arpa}/;

  my $packet = Net::DNS::Packet->new($domain, $self->{RP} ? 'RP' : 'TXT');
  #$packet->push('question', Net::DNS::Question->new($domain, 'RP', 'IN'));

  return $packet;
}

sub _reverse_ip {
  my $self = shift;
  my ($ipk) = @_;
  
  my $ipr;
  my $oldfh = select();
  local *NULL;
  
  if ($self->{NOISY_NET_IP}) {
    require File::Spec;
    open(NULL, ">" . File::Spec->devnull())
      or return $self->_e("Failed to open " . File::Spec->devnull() . " for Net::IP " . $Net::IP::VERSION . " kludge: $!");
    $oldfh = select(NULL);
    print __PACKAGE__ . " shut up STDOUT to work around debug output in Net::IP::reverse_ip.\n";
  }
  
  $ipr = $self->{$ipk}->reverse_ip()
           or return $self->_e("Reverse failed: " . $self->{$ipk}->error());
  
  if (select($oldfh) ne $oldfh) {
    close (NULL);
  }
  return $ipr;
}

=pod

=item send_packet



=cut

sub send_packet {
  my $self = shift;
  my ($packet) = @_;
  
  $packet ||= $self->create_packet();
  return undef unless $packet;

  $self->{resolver} ||= Net::DNS::Resolver->new(
                          retry => 3,
                          udp_timeout => 30,
                          tcp_timeout => 30,
                        );

  return $self->{resolver}->send($packet);
}

=pod

=item process_packet



=cut

sub process_packet {
  my $self = shift;
  my ($packet) = @_;

  $packet ||= $self->send_packet();
  return undef unless $packet;

  if ($packet->header->ancount() > 0) {
    my $type = $self->{RP} ? 'RP' : 'TXT';
    my @answer = $packet->answer();
    while (@answer) {
      last if $answer[0]->type() eq $type;
      shift(@answer);
    }
    if (@answer) {
      if ($self->{RP}) {
        $self->{MAILBOX} = $self->_parse_rp($answer[0]);
      }
      else {
        $self->{RESULT}  = $self->_parse_txt($answer[0]);
      }
    }
  }
  
  if ($self->{RP} or not $self->{query_rp}) {
    shift(@{$self->{QUEUE}});
    $self->{RP} = 0;
    return 0 if $self->{RESULT};
    return 0 unless @{$self->{QUEUE}};
    return 1;
  }
  else {
    $self->{RP} = 1;
    return 2;
  }
  
  return $self->_e("Must not happen");
}

sub _parse_txt {
  my $self = shift;
  my ($data) = @_;
  
  $data = $data->rdatastr();
  $data =~ /^"\s*([01])\s*"$/;
  return q(unknown) unless $1;
  return qw(fail pass)[$1];
}

sub _parse_rp {
  my $self = shift;
  my ($data) = @_;
  
  $data = $data->mbox() || '';
  $data =~ s/(?<!\\)\./@/;
  $data =~ s/\\\././g;
  return $data;
}


1; # We are so true.
__END__

=back

=head1 THE PROTOCOL

The MTAMark protocol is very simple:

For a given IP address it will look in the Reverse DNS space for a 
matching TXT record.  It uses the sub-zone C<_send._smtp._srv>.  The
TXT record may contain a single character:  Either C<1> if the host(s)
behind the IP address are allowed to act as a MTA or C<0> if not.

For example:  The mailserver has the IP address 10.20.30.40.  The 
following query will be sent:

  _send._smtp._srv.40.30.20.10.in-addr.arpa IN TXT

The result can be either C<0> (C<fail>, must not be an MTA) or C<1>
(C<pass>, may be an MTA).  Everything else isn't valid (C<unknown>).
If the specification is followed strictly, C<unknown> must be interpreted
as C<fail>.

If there is a MTAMark entry, the RP entry for that domain should be
retrieved, too:

  _send._smtp._srv.40.30.20.10.in-addr.arpa IN RP

=head1 THE FLOW

It is possible to hook into the internal flow of the Mail::MTAMark::Query
object.  You should have a look at the C<result> routine to see how it
works internally, but in pseudocode it works like this:

  # @queue = ($ipv4txt, $ipv4rp, $ipv6txt, $ipv6rp);
  while (1) {
    $question = create_packet();
    $answer   = send_packet($question);
    $more     = process_packet($answer); # shifts @queue
    last unless $more;
  }

The queue is actually a bit more dynamic, the point is that it might be 
necessary to send more than one DNS query (unless query_rp is unset and
only one IP was given).

To keep this from blocking your application, it is possible to do the 
packet sending on your own.  Something like this is possible:

  $query    = Mail::MTAMark::Query->new(ip => "10.20.30.40");
  $resolver = Net::DNS::Resolver->new();
  while (1) {
    my $question = $query->create_packet() || die $query->error();
    my $socket   = $resolver->bgsend($packet);
    until ($resolver->bgisready($socket)) {
      # do other cool stuff
    }
    my $answer   = $resolver->bgread($socket) || die $resolver->errorstring();
    my $more     = $query->process($answer);
    die $query->error() unless defined $more;
    last unless $more;
  }

=head1 PREREQUISITES

L<Net::IP>
L<Net::DNS>

=head1 SEE ALSO

L<Net::DNS::Resolver/ENVIRONMENT>
L<http://mtamark.berlios.de/>
L<Mail::SPF::Query>


=cut
