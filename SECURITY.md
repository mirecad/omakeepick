# Security policy

OmaKeePick handles KeePass master passwords and the secrets in your database, so security
reports are very welcome.

## Reporting a vulnerability

Report it privately through
[GitHub's private vulnerability reporting](https://github.com/mirecad/omakeepick/security/advisories/new),
not in a public issue. Please include:

- the version (`omakeepickd --version`),
- what an attacker needs: another local user, a process running as you, physical access…
- steps to reproduce.

The fix ships in a new release, and the advisory is published once that release is out.

## Supported versions

Only the latest release gets fixes. `omarchy plugin update mirecad.omakeepick` installs it.

## Scope

In scope are `omakeepickd` and the shell plugin, for example:

- a password, PIN, note or TOTP secret reaching the shell process, a command line, a log or a
  file;
- the socket accepting a connection from another user;
- getting past the quick-unlock PIN without knowing it, or past its three-attempt limit;
- the database staying unlocked after an idle lock, screen lock, suspend or *Close database*.

Bugs in KeePass or the KDBX format, `wtype`, `wl-clipboard` or Omarchy belong upstream.
