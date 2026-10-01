# ADR 0002 — Rename "Secure Input" to "Doorman"

## Decision

Rename the plugin and every internal identifier (manifest id, plugin
directory, broker's Python package, systemd unit, runtime directory,
scripts, and environment variables) from `secure-input`/`SECURE_INPUT` to
`doorman`/`DOORMAN`.

## Reason

"Secure Input" collides with an already-established OS security term
("Secure Input Mode", keyboard protection against keyloggers) that
describes something different from what this plugin does. The name was
also generic compared to the other plugins installed in the catalog (Radio
Atlas, Loose Ends, Snipper, Port Watch), which lean toward more
distinctive names.

"Doorman" describes the plugin's central metaphor without ambiguity: a
process knocks on the door asking for `sudo`, and a person — only them, in
a local window — decides whether to let it in.

## Consequence

The manifest id changes (`mauricio.secure-input` → `mauricio.doorman`),
which makes Omarchy treat this as a different plugin from the bar layout's
point of view: `~/.config/omarchy/shell.json` stores active widgets by id,
so the old reference had to be updated by hand for the widget to keep
showing up on the topbar after the migration — renaming a plugin's id
doesn't automatically carry over its position on the bar.
