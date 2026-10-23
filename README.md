# canary

Every new release on npm and PyPI, **read before anyone installs it**.

**Live:** [canarywatch.live](https://canarywatch.live) · X: [@canarywatch_sol](https://x.com/canarywatch_sol) · agent json: [state](https://api.canarywatch.live/state.json) · [catches](https://api.canarywatch.live/catches.json)

An agent watches the npm and PyPI feeds. Each new release is fetched, unpacked **in memory**, and
read line by line: install hooks, obfuscation, secret files next to a network call, wallet grabs,
shell shapes, stray binaries, lookalike names. **It never installs and never executes anything.**
When the rules trip, the package goes on the wall with the exact lines that put it there. When the
public record (OSV / OpenSSF malicious-packages) confirms it, it says `confirmed`.

The site shows the wall, a live log, the rules read straight from the agent, and a box where you
paste your own `package.json`, lockfile or `requirements.txt` and see which names are on the record.

## What it is, and is not

- **Static analysis only.** `fetch.py` keeps bytes; there is no install, no import, no subprocess
  anywhere in the agent. The box runs it in a systemd sandbox that cannot write outside its data
  directory.
- **Evidence-bound.** A catch is a list of findings, each with a file, a line and the text. A name
  never appears on the wall without them.
- **`confirmed` is the record's word, not ours.** Our rules can only say `tripped`. Only a public
  advisory at OSV makes a package `confirmed`.
- **Established packages are not shamed.** A year old, or 50k downloads a week: heuristics alone
  never put it on the wall. The one exception is a hijack: a version younger than 72 h carrying one
  strong finding.
- **Mistakes stay visible.** A wrong catch is cleared in `cleared.json` with a reason and stays on
  the wall, marked. When the rules change, the agent re-reads every tripped catch and drops what no
  longer holds, as a public event. The recall number (how often the rules tripped before the record
  did) is published even when it is unflattering.

## Run it

    pip install -r requirements.txt
    python -m agent doctor                 # what this machine can reach
    python -m agent scan npm left-pad      # read one package, print the verdict and the lines
    python -m agent check package.json     # a dependency file against the record
    cp config.example.toml config.toml
    python -m agent run                    # watch the feeds, serve the files

    pytest                                 # the engine's logic, tested with benign fixtures only

## Deploy

    DOMAIN=api.example.com bash deploy/push.sh      # to the box, in one ssh session

`deploy/install.sh` sets up a sandboxed `canary` user and service, a Caddy site for https, the
static site zipped for a Netlify drop at `/site.zip`, and the source over http at `/canary.git`.
It adds its own Caddy site file, so it can share a box with other services.

## Files the site reads

`state.json` (counters, rates, feed health, the recall number), `catches.json` (the wall),
`watch.json` (the quiet list), `events.json` (the live log), `rules.json` (the method, as the
site prints it). Two POSTs: `/check` (a dependency file → what is on the record) and `/scan`
(one package → the full verdict). Nothing a person sends is ever written.

## Layout

    agent/      rules.py (the seven rules), fetch.py (bytes, never an install), osv.py (the record),
                manifests.py (dependency files), server.py (http), main.py (the loop), __main__.py (cli)
    site/       static html + css + js, reads the agent's json; sample/ for local previews
    deploy/     install.sh, push.sh, the sandboxed systemd unit, the Caddy site, mint.sh
    tests/      the engine's logic on benign fixtures
