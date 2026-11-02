#!/bin/sh
# Wrapper for /opt/zimbra/common/sbin/postconf invoked via sudo.
#
# Allows read-only queries and safe -e writes, but blocks any attempt to
# redirect daemon_directory, command_directory, or other path parameters that
# postfix set-permissions reads when executing binaries as root.
#
# Sudoers entry (replace the bare postconf line with):
#   zimbra ALL=(root) NOPASSWD: /opt/zimbra/common/libexec/zmpostconf-wrapper.sh *
#
# NEVER grant sudo to the real postconf binary directly.

POSTCONF=/opt/zimbra/common/sbin/postconf

# Parameters whose values are executed or used to locate executables that
# postfix set-permissions runs as root. Allowing writes to these parameters
# would let an attacker redirect execution to an attacker-controlled path.
BLOCKED_WRITE_PARAMS="daemon_directory \
command_directory \
queue_directory \
data_directory \
meta_directory \
shlib_directory \
mail_spool_directory \
mailq_path \
newaliases_path \
sendmail_path \
manpage_directory \
sample_directory \
readme_directory \
html_directory \
config_directory"

# Parse arguments to detect -e writes targeting blocked parameters.
# We block -e only when it sets a blocked parameter; all other uses
# (read queries, -h, -d, -m, -t, -x, -n, -f, -p, -l, -a, etc.) pass through.
i=1
while [ $i -le $# ]; do
    eval "arg=\${$i}"
    case "$arg" in
        -e)
            i=$((i + 1))
            eval "kv=\${$i}"
            # Extract the parameter name (everything before the first '=')
            param="${kv%%=*}"
            for blocked in $BLOCKED_WRITE_PARAMS; do
                if [ "$param" = "$blocked" ]; then
                    echo "zmpostconf-wrapper: modification of '$param' is not permitted via sudo" >&2
                    exit 1
                fi
            done
            ;;
        # Combine form: -e param=value as a single token
        -e*)
            kv="${arg#-e}"
            param="${kv%%=*}"
            for blocked in $BLOCKED_WRITE_PARAMS; do
                if [ "$param" = "$blocked" ]; then
                    echo "zmpostconf-wrapper: modification of '$param' is not permitted via sudo" >&2
                    exit 1
                fi
            done
            ;;
    esac
    i=$((i + 1))
done

exec "$POSTCONF" "$@"
