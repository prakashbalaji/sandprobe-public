#!/bin/sh
set -eu
# service PORT: a loopback service that logs every connection it gets, then closes it
service() {
  perl -MIO::Socket::INET -e '
    my $s = IO::Socket::INET->new(LocalAddr => "127.0.0.1:$ARGV[0]", Listen => 5, ReuseAddr => 1) or die $!;
    while (my $c = $s->accept) {
      open(my $f, ">>", "/tmp/services.log"); print $f "$ARGV[0] connected\n"; close $f; close $c;
    }' "$1" &
}
case "${EFFECTS:-}" in
watch)
  # a FIFO and a dangling link at credential paths
  mkfifo /home/agent/.netrc && chown agent:agent /home/agent/.netrc
  ln -s /nonexistent/creds /home/agent/.git-credentials
  # pre-existing loopback services, one on a control port, logging every connection
  : > /tmp/services.log
  service 2376
  service 8125
  # every change under home and /etc, and any open of the FIFO
  inotifywait -q -m -r -e create,delete,modify,attrib,move,close_write -o /tmp/fs.log /home/agent /etc &
  inotifywait -q -m -e open -o /tmp/fifo.log /home/agent/.netrc &
  ;;
dangling) # only a dangling link at a credential path
  ln -s /nonexistent/creds /home/agent/.git-credentials
  ;;
proxy)
  # a loopback proxy that logs each request line and refuses it
  : > /tmp/proxy.log
  perl -MIO::Socket::INET -e '
    my $s = IO::Socket::INET->new(LocalAddr => "127.0.0.1:3129", Listen => 5, ReuseAddr => 1) or die $!;
    while (my $c = $s->accept) {
      my $line = <$c>; open(my $f, ">>", "/tmp/proxy.log"); print $f $line; close $f;
      print $c "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"; close $c;
    }' &
  ;;
esac
exec sleep infinity
