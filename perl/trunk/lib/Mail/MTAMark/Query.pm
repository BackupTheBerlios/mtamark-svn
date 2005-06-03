package Mail::MTAMark::Query;

use 5.006;
use strict;
use warnings;

use Net::IP qw();
use Net::DNS qw();

use vars qw($VERSION);

$VERSION = '0.001';


sub new {
  my $class = shift;
  $class = ref($class) || $class;
  
  my %self = (
    ip   => undef,
    ipv4 => undef,
    ipv6 => undef,

    rp => 1,
    
    resolver => undef,
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

sub error {
  my $self = shift;
  return $self->{ERROR};
}

sub _e {
  my $self = shift;
  $self->{ERROR} = $_[0];
  return undef;
}

sub create {
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

sub send {
  my $self = shift;
  my ($packet) = @_;
  
  $packet ||= $self->create();
  return undef unless $packet;

  $self->{resolver} ||= Net::DNS::Resolver->new(
                          retry => 3,
                          udp_timeout => 30,
                          tcp_timeout => 30,
                        );

  return $self->{resolver}->send($packet);
}

sub process {
  my $self = shift;
  my ($packet) = @_;

  $packet ||= $self->send();
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
  
  if ($self->{RP} or not $self->{rp}) {
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

sub result {
  my ($self) = @_;
  
  return $self->{RESULT} unless $self->{RESULT} eq q(none);
  return $self->{RESULT} unless @{$self->{QUEUE}};
  
  my $res;
  do {
    $res = $self->process();
    return q(error) unless defined $res;
  }
  while ($res);
  
  return ($self->{RESULT});
}
