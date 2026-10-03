#!/bin/sh
# Start the IndraMQTT kernel and the edge in one container.
#
# The kernel resolves the configuration: indra.toml, conf.d, the INDRA_*
# variables and the flags. Then the kernel prints the listener settings
# for the edge. Thus you set a listener in one place only.
#
# If one process stops, the container stops. The orchestrator then
# starts the container again.
set -eu

EDGE_EBIN=${INDRA_EDGE_EBIN:-/usr/lib/indramqtt/edge/ebin}

# A configuration error stops the script here. No listener is open yet.
edge_args=$(indramqtt "$@" --print-edge-args)

indramqtt "$@" &
kernel=$!

# Each line is one edge argument. A value can contain spaces. Split the
# text at the line ends only.
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
# Exit status: 0 for a stop that the operator requested, 1 if a process
# stopped by itself.
status=1
trap 'status=0; stop' TERM INT

while kill -0 "$kernel" 2>/dev/null && kill -0 "$edge" 2>/dev/null; do
    sleep 1
done
stop
wait "$kernel" 2>/dev/null || true
wait "$edge" 2>/dev/null || true
exit "$status"
