# culprit

*Find out what's slowing your PC down, who it belongs to, and end it if you want to.*

`culprit` is a small Windows command-line tool. Run it and you get a live list of what is using the machine, ranked by how much pressure each application has put on it **over time**, not just this second. Press `D` on one to see who published it, where it lives and which account it runs as. Press `K` to end it.

One native exe (about 550 KB). No installer, no runtime, no admin, no network, no telemetry.

It is the interactive sibling of [hog](https://github.com/markcastle/hog): hog takes a quick snapshot and exits; culprit stays open, remembers, and can act.

## Install

In PowerShell (no admin needed):

```powershell
irm https://raw.githubusercontent.com/markcastle/culprit/master/install.ps1 | iex
```

That downloads the latest release into `%LOCALAPPDATA%\Programs\culprit` and adds it to your user PATH. Run it again to upgrade. Or just grab `culprit.exe` from the [releases page](https://github.com/markcastle/culprit/releases) and put it anywhere.

## Use

```text
C:\>culprit

 CULPRIT                                                     • LIVE
 Impact over the last hour  ·  42m recorded  ·  tracking on

 PROCESS                                      CPU       RAM IMPACT↓
 ──────────────────────────────────────────────────────────────────
 Desktop Window Manager                      4.0%    7.2 GB      49
 Claude (16)                                 9.1%    2.2 GB      44
 Egnyte Drive                                1.9%    118 MB       9
 Task Manager                                7.2%    289 MB       6

 ↑↓ Select   D Details   K Kill   T Tree   H 1h/24h   S Sort   Q Quit
```

| Key | What it does |
| --- | --- |
| `↑` `↓` `PgUp` `PgDn` | Move the selection (it stays on the same app as the list reorders) |
| `D` or `Enter` | Details: publisher, signature, location, account, start time, parent, services |
| `T` | The real parent/child process tree for that app; pick any single process |
| `K` | End the selected process, or it and its descendants. Always asks first |
| `H` | Switch Impact between the last hour and the last 24 hours |
| `S` | Sort by Impact, CPU or RAM |
| `Q` / `Esc` | Quit / back |

Plain commands, for scripts or a quick look:

```text
culprit list                 one-off table (also what you get when output is piped)
culprit who <pid|name>       who owns a process
culprit kill <pid> [--tree]  end a process; shows what will die and asks first
culprit track on|off|status  background history (see below)
```

## Impact

Impact is a score from 0 to 100 for how much sustained pressure an application has put on the machine over the selected window. It is a way of ranking suspects, not a measurement of how much slowdown something caused.

- **CPU, up to 70 points.** Average share of the whole machine's CPU, reaching 70 at a sustained 15%.
- **Memory, up to 30 points.** Average private memory as a share of installed RAM, reaching 30 at 12%. Memory held while the machine has plenty free counts half; the weight rises to full as RAM in use goes from 50% to 90%.
- **Averaged over everything observed in the window**, including time the app was not running. Five percent all hour outranks one frantic minute.

Until at least a minute has been observed it shows `—` rather than making a number up. The header always says how much history the score is based on.

## History and background tracking

Run `culprit` on a fresh machine and it works immediately: it samples while it is open and scores build up from there.

To have history ready *before* you open it:

```text
culprit track on
```

This registers an ordinary per-user scheduled task that starts a headless copy of the same exe when you sign in (no admin, no Windows service), and starts it now. `culprit track off` stops it and removes the task. Only one collector runs per user.

History is deliberately simple: one row of totals per application per minute. The live view keeps the last 24 hours in memory (around a megabyte). Whoever is recording appends finished minutes to a plain tab-separated text file per day in `%LOCALAPPDATA%\Culprit\`, which is how history survives a restart and how the collector hands it to the live view. Files older than 7 days are deleted. There is no database.

If nothing was recording for a while, that time is simply absent: scores average over observed time only, and the header shows how much there is.

## Ending processes safely

- Nothing is ever ended without an explicit confirmation that says how many processes will die.
- Immediately before acting, the process is re-identified by PID **and** creation time, so a recycled PID can never be hit by mistake.
- "Process tree" means actual descendants, re-read at that moment. It never means "everything with the same name".
- Critical Windows processes (System, csrss, lsass, winlogon, anything Windows flags as critical) and culprit's own collector are refused.
- Partial failures are listed process by process.
- If Windows says no, culprit offers `Administrator permission required. Elevate?` and, on yes, uses a normal UAC prompt to run a temporary elevated copy for just those processes. The main window never runs elevated. Protected processes stay protected; there is no attempt to get around that.

## What you may see as `Restricted`

Without admin, Windows will not reveal the account of processes that belong to other users or the system. culprit shows `Restricted` or `Unavailable` rather than guess. Publisher, signature and location are still shown for those.

## Build

You do not need to: every push is built and tested by GitHub Actions, and pushing a `v*` tag publishes a release with `culprit.exe` and its SHA-256.

```text
git tag v0.1.0
git push origin v0.1.0
```

To build locally anyway (Visual Studio 2022 with C++, CMake 3.24+):

```text
cmake -S . -B build -A x64
cmake --build build --config Release
ctest --test-dir build -C Release
```

## How it is put together

| File | Job |
| --- | --- |
| `src/sampler.cpp` | One `NtQuerySystemInformation` call per sample: every process, no handles opened |
| `src/score.cpp` | The Impact formula. Pure, unit tested |
| `src/recorder.cpp` | Turns samples into per-minute totals. Pure, unit tested |
| `src/history.cpp` | In-memory history and the text journal |
| `src/proctree.cpp` | Grouping, parent/child trees, PID-reuse guards. Pure, unit tested |
| `src/inspect.cpp` | On-demand details: path, version info, Authenticode and catalog signatures, account, services |
| `src/kill.cpp` | Termination safeguards and UAC elevation |
| `src/track.cpp` | Scheduled task and the headless collector |
| `src/engine.cpp` | Background sampling thread shared by the UI and the collector |
| `src/ui.cpp` | The terminal interface (VT sequences, no flicker, no screen clearing) |

Windows 10 or 11, x64.
