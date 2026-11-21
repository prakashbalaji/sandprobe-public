# A stand-in Docker socket, mode 0666: it accepts and does nothing (the holes fixture's stub).
use IO::Socket::UNIX;
unlink '/run/docker.sock';
my $s = IO::Socket::UNIX->new(Type => SOCK_STREAM(), Local => '/run/docker.sock', Listen => 5) or die $!;
chmod 0666, '/run/docker.sock';
sleep 3600 while 1;
