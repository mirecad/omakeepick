#!/bin/sh
# Stands in for an `open-db` helper whose file read never returns: it never reports the files
# as read. After a moment it gives up and reports, as its error, how many bytes it was sent.
sent=$(timeout 1 cat | wc -c)
printf '{"code":"failed","message":"%s"}\n' "$((sent))" >&2
exit 1
