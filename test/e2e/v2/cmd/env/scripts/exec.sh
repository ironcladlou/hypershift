#!/bin/sh
# Signal-safe command wrapper. Prevents the shell exec optimization
# which causes double SIGINT delivery when running under mise.
# Without this, sh -c "single-command" replaces itself with the
# command, making it mise's direct child. Mise then forwards SIGINT
# to it (in addition to the terminal's process-group SIGINT).
#
# With this wrapper, mise's child is this shell process, which
# absorbs the forwarded signal. The command only receives the
# terminal signal.
"$@"
exit $?
