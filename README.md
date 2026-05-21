# tup

CLI for the on-prem Foundries.io OTA stack. Driver for the no-CI publish
flow described in REWRITE-PLAN-v2 §4.3.

```
tup namespace create --name acme               # POST /api/v1/user_repo
tup namespace list                              # GET  /api/v1/user_repo
tup namespace show <repo-id>                    # GET  /api/v1/user_repo/<rid>/root.json

# (later sessions, when targets pipeline lands)
tup publish --namespace acme \
             --ostree-repo ~/yocto/.../ostree_repo \
             --hardware-id raspberrypi4-64 \
             --tag main \
             --app web=./apps/web
```

Designed to be friendly to both humans (clear text output) and agents
(`--json` flag on every command per v2 §7.1 discoverability).

## Layout

```
cmd/tup/         entry point + subcommand wiring
internal/api/      typed client for tufd + (later) ota-lite
```

## Local development

```
make build       # compile cmd/tup
make test        # unit + integration
```

Requires Go 1.24.
