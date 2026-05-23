# tup

Operator-side CLI for the **tuf on-prem** OTA stack. Drives `tufd`'s
admin surface (publish, waves, configs, compose-apps, device
registration, key export) from the host so an operator can run a
factory without a CI pipeline in the loop.

## Commands

```
tup project create <name>                          create project
tup project list                                   list projects
tup project show <project-id>                      dump signed root role
tup project rotate <project-id>                    online dual-key root rotation
tup project validate <project-id>                  TUF chain walk + verify
tup project create-with-key --name … --root-pubkey <file>
tup project stage-rotation <project-id> --new-pubkey <file>
tup sign-rotation --tosign … --old-key … --new-key …
tup sign-bootstrap --tosign … --key … -o …
tup project finalize-create / finalize-rotation

tup publish <project-id> <name> <version>
tup unpublish <project-id> <name> <version>

tup project app push --name … --version … --from <bundle.tgz> <project-id>
tup project app list <project-id>
tup project app rm   --name … --version … <project-id>

tup project config set --name … --from <file>   <project-id>
tup project config list                          <project-id>
tup project config rm  --name …                  <project-id>

tup project wave create --name … --targets k1,k2  <project-id>
tup project wave add    --name … --device-id …    <project-id>
tup project wave remove --name … --device-id …    <project-id>

tup project pin-device   --device-id … --target …  <project-id>
tup project unpin-device --device-id … …           <project-id>
tup project list-pins    [--device-id …]           <project-id>

tup project register-device --device-id … --out-dir <dir>   <project-id>
tup project get-ca          --out <ca.pem>                  <project-id>

tup project backup  --out <bundle.tgz>             <project-id>
tup project restore --in  <bundle.tgz>

tup project export-offline-keys --out <creds.tgz>  <project-id>
                                                   # fioctl-compat offline-creds.tgz
                                                   # for `fioctl waves init -k …`

tup ostree push        <project-id> --from <local-repo>
tup ostree gen-delta   <project-id> --from … --to …
tup ostree list-deltas <project-id>

tup project import-build <project-id> --token … --factory …
```

## Environment

```
TUP_URL           tufd base URL (default $TUP_URL or http://localhost:19010)
TUP_ADMIN_TOKEN   OSF-TOKEN value (default $TUFD_ADMIN_TOKEN)
```

## Build

```
go build -o bin/tup ./cmd/tup
```
