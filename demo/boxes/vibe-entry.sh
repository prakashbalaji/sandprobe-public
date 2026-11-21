#!/bin/sh
# Supabase's local stack needs Docker, so the agent was handed the socket.
perl /opt/app/dockersock.pl &
# The agent started the dev server with .env loaded, as its own user: the server's environment holds every key.
cd /home/agent/booking-app
exec setpriv --reuid=agent --regid=agent --init-groups sh -c 'set -a; . ./.env; set +a; exec perl /opt/app/devserver.pl'
