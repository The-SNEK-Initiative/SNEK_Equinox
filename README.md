# SNEK Equinox
 I would like to thank Nightmare-Eclipse for the inspiration (not personal) from the project UnDefend - https://gitlab.com/nightmare-eclipse/un-defend:
 > Now funnily enough, I found a way to lie to the EDR web console to show that defender is up and running with the latest update even if it's not. I was thinking about publishing the code but after thinking about it, it will cause waaay too much damage so I think I'll keep that stuff stashed for now.

\- Nightmare-Eclipse

## So what do we have here??

Its PoC implementation that in theory demonstrates telemetry spoofing against Windows Defender EDR. It attempts to demonstrate a TOCTOU race condition attack on the defender signature update mechanism. It should make the console display a protected status, while protection is disabled.

But this is all in theory, in practice, neither I nor none of my associates have had time to properly test this and confirm if it works or not, and what bugs it might possibly have, so any feedback is as usual appreciated.

## How do I build this??

```
build.bat
```

Output binaries: `bin\run.exe`, `bin\Equinox.exe`, `bin\spoof.exe`, `bin\vers.exe`

You dont get any precompiled ones this time.

## Execution

### UnElevated Mode
```
bin\Equinox.exe
```
- Locks signature files to prevent loading
- Defender appears to have signatures but cant load them
- Local threat detection should be disabled by it
- Cloud console should show last cached state (still might appear healthy if not recently queried)

### Elevated Mode
```
bin\run.exe
```
Requires administrator privileges. sequence:
1. `spoof.exe` - Sets health registry values
2. `vers.exe` - Sets version registry values
3. `Equinox.exe` - Locks signature files

I'm not going to go more in depth with this, ya'll can figure a lot of it out yourself ;P