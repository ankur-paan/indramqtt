#!/bin/sh
# Start the IndraMQTT kernel and its edge in one container.
#
# The kernel resolves the configuration (indra.toml, conf.d, INDRA_*
# variables, flags) and prints the listener settings for the edge, so a
# listener is configured in one place. The container exits as soon as
# either process exits, and the orchestrator restarts it.
set -eu

EDGE_EBIN=${INDRA_EDGE_EBIN:-/usr/lib/indramqtt/edge/ebin}

# A configuration error stops here, before anything listens.
edge_args=$(indramqtt "$@" --print-edge-args)

indramqtt "$@" &
kernel=$!

# One edge argument per line; values may hold spaces, so split on newlines only.
set --
old_ifs=$IFS
IFS='
'
for arg in $edge_args; do
    set -- "$@" "$arg"
done
IFS=$old_ifs

erl -noshell -noinput -pa "$EDGE_EBIN" "$@" \
    -eval '{ok, _} = application:ensure_all_started(indra_edge), timer:sleep(infinity).' &
edge=$!

stop() {
    kill -TERM "$kernel" "$edge" 2>/dev/null || true
}
# A requested stop exits 0; a process that died on its own exits 1.
status=1
trap 'status=0; stop' TERM INT

while kill -0 "$kernel" 2>/dev/null && kill -0 "$edge" 2>/dev/null; do
    sleep 1
done
stop
wait "$kernel" 2>/dev/null || true
wait "$edge" 2>/dev/null || true
exit "$status"
