#!/bin/sh
# Wrapper for /opt/zimbra/common/sbin/postfix invoked via sudo.
#
# Only the subcommands required for normal Zimbra MTA operation are allowed.
# set-permissions is explicitly excluded: it executes binaries located via
# daemon_directory as root, creating a privilege-escalation vector when
# combined with unrestricted postconf write access.
#
# Sudoers entry (replace the bare postfix line with):
#   zimbra ALL=(root) NOPASSWD: /opt/zimbra/common/libexec/zmpostfix-wrapper.sh *
#
# NEVER grant sudo to the real postfix binary directly.

POSTFIX=/opt/zimbra/common/sbin/postfix

ALLOWED_SUBCOMMANDS="start stop reload abort flush check status upgrade-configuration"

BLOCKED_SUBCOMMANDS="set-permissions"

if [ $# -lt 1 ]; then
    echo "zmpostfix-wrapper: subcommand required" >&2
    exit 1
fi

subcommand="$1"

for blocked in $BLOCKED_SUBCOMMANDS; do
    if [ "$subcommand" = "$blocked" ]; then
        echo "zmpostfix-wrapper: subcommand '$subcommand' is not permitted via sudo" >&2
        exit 1
    fi
done

allowed=0
for cmd in $ALLOWED_SUBCOMMANDS; do
    if [ "$subcommand" = "$cmd" ]; then
        allowed=1
        break
    fi
done

if [ "$allowed" -ne 1 ]; then
    echo "zmpostfix-wrapper: subcommand '$subcommand' is not in the allowed list" >&2
    exit 1
fi

exec "$POSTFIX" "$@"
