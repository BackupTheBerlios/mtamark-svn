use lib 'lib';
use Mail::MTAMark::Query;

my ($q, $e) = Mail::MTAMark::Query->new(@ARGV);
die $e unless $q;

print $q->result();
print $q->error();

exit 0;

my $p = $q->create() || die $q->error();;
print $p->string();

my $r = $q->send($p);
print $r->string() or die $q->error();

my $x = $q->process($r);
print $x;


