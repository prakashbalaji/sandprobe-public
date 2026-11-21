# The app's dev server: answers on 5173 and does nothing else.
use IO::Socket::INET;
my $s = IO::Socket::INET->new(LocalPort => 5173, Listen => 5, ReuseAddr => 1) or die $!;
while (my $c = $s->accept) { print $c "HTTP/1.0 200 OK\r\n\r\nstudio booking\n"; close $c }
