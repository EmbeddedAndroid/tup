# fioup

CLI for the on-prem Foundries.io OTA stack. Driver for the no-CI publish
flow described in REWRITE-PLAN-v2 §4.3.

```
fioup factory create --name acme               # POST /api/v1/user_repo
fioup factory list                              # GET  /api/v1/user_repo
fioup factory show <repo-id>                    # GET  /api/v1/user_repo/<rid>/root.json

# (later sessions, when targets pipeline lands)
fioup publish --factory acme \
             --ostree-repo ~/yocto/.../ostree_repo \
             --hardware-id raspberrypi4-64 \
             --tag main \
             --app web=./apps/web
```

Designed to be friendly to both humans (clear text output) and agents
(`--json` flag on every command per v2 §7.1 discoverability).

## Layout

```
cmd/fioup/         entry point + subcommand wiring
internal/api/      typed client for fiotufd + (later) ota-lite
```

## Local development

```
make build       # compile cmd/fioup
make test        # unit + integration
```

Requires Go 1.24.
