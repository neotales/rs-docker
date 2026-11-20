# Releasing

Publishing runs from `release.yml`. It is driven by a tag and it authenticates
with a short-lived crates.io token obtained over OIDC. There is no
`CARGO_REGISTRY_TOKEN` secret in this repository.

## The version rule

The tag is `v` plus the version every publishable crate in `Cargo.toml`
carries. Tag `v0.0.0-alpha.1` publishes only if all five manifests say
`version = "0.0.0-alpha.1"`. The `version` job fails the run otherwise, so a tag
can never publish a version that differs from what is in the tree.

The five crates share a version on purpose. They are a group, and the engine
names the BuildKit crate by version: a release where only one of them moved
would be a tree no reader could describe with one tag.

Bump the version in all five manifests, commit, push, then tag that commit:

```sh
cargo publish --dry-run -p neotales-oci-distribution
git tag v0.0.0-alpha.1
git push origin dev
git push origin v0.0.0-alpha.1
```

The one exception is a new crate's first version, which is uploaded by hand and
never from a tag. That is the next section.

## Publish order

`release.yml` does not use `cargo publish --workspace`. It reads
`cargo metadata`, drops anything marked `publish = false`, sorts the rest by
their dependencies on each other, and names each package to `cargo publish` in
turn. A package whose dependency was uploaded seconds ago may fail once while
the index catches up; the job retries that case and a rate limit, and nothing
else.

For the current set the order is:

1. `neotales-oci-distribution`
2. `neotales-docker-buildkit`
3. `neotales-docker-bake`
4. `neotales-docker-compose`
5. `neotales-docker` (names `neotales-docker-buildkit`)

A helper crate that should never be published is marked `publish = false` in
its manifest and is then absent from the list. There is no such crate today,
and `cargo publish -p <name>` names packages one at a time so one could not be
uploaded by accident.

A re-run skips a version that is already on crates.io. Do not republish a
version, and do not delete or move the tag.

## First publish of a new crate

crates.io trusted publishing cannot create a brand-new crate. The OIDC exchange
needs a crate that exists and a trusted publisher configured on it, so a cold
start over OIDC is rejected by crates.io. Do not try to build one.

The first version of a new crate is `0.0.0-alpha.0`. Not `0.0.0-alpha.1` and
not `0.1.0`. The first upload is manual, and a manual upload needs a version
nothing else has claimed.

The first upload goes through `/home/dev/work/rs/publish.sh <dir>`. That script
lives beside this folder, in `~/work/rs`, and is deliberately not copied into
the crate repository: it is how the first version of every crate is uploaded,
not part of any one crate.

1. Set `version = "0.0.0-alpha.0"` in all five manifests, commit it, and leave
   the working tree clean. Do not publish from a tree with uncommitted changes.
2. Run the script with each crate's directory, in the order above:

   ```sh
   ~/work/rs/publish.sh oci
   ~/work/rs/publish.sh buildkit
   ~/work/rs/publish.sh bake
   ~/work/rs/publish.sh compose
   ~/work/rs/publish.sh engine
   ```

   The script reads the token itself and passes it to `cargo` through the
   environment. Do not put a token on the command line, in the repository, or
   in shell history.

   The engine's manifest names `neotales-docker-buildkit` by version, so the
   BuildKit upload must reach the index before the engine upload starts. If the
   engine upload fails with `failed to select a version for the requirement`,
   wait a minute and run that one command again.

3. Add the trusted publisher on crates.io for each crate, in the crate's
   settings: owner `neotales`, repository name `rs-docker`, workflow filename
   `release.yml`, and an empty environment. Leave the environment field empty.
   The `publish` job in `release.yml` does not set an environment, and
   crates.io compares the two fields: an environment name here that the job does
   not set, or the reverse, fails the token exchange and nothing else fails with
   it. If someone later sets an environment name on crates.io, the job must set
   that exact name.
4. Bump to the next version and let tags take over. Do not run `publish.sh` for
   these crates again.

The release run for that first version skips every crate, because the versions
are already uploaded. The tag is provenance for the first version, not its
publish trigger. Every later version publishes from its `v*` tag.

If a crate name is taken on crates.io by someone else, stop. A rename is a
different repository setup, not a flag.

`cargo package` includes every tracked file, so `.github/`, `RELEASE.md` and
`fixtures/` ship inside the published crates unless the manifest excludes them.
That is harmless. Exclude them if package size matters. The README style guide
lives at `~/work/rs/README.STYLE.md` and is not part of a crate.

## Later releases

1. Bump the version in all five manifests and commit it. `Cargo.lock` is
   committed on purpose, so run `cargo build` and commit the updated lockfile
   with it. The lockfile is what the scheduled audit checks.
2. Push the commit.
3. Tag it `vX.Y.Z` and push the tag.
4. The workflow runs the checks, then the dry run, then publishes in dependency
   order with a token minted for that run.

A manual run, `workflow_dispatch`, runs the checks and the dry run only. It
never publishes, whatever branch it is started from.

After the manual first upload is done, switch each crate to Trusted Publishing
Only mode on crates.io. That rejects token publishes everywhere, so a token
cannot publish these crates later.

## What is not allowed

- `pull_request_target` and `workflow_run` are not used anywhere, and must not
  be added. Both can run untrusted code with publishing credentials in scope.
- No long-lived crates.io token in GitHub secrets for this workflow. The job
  reads `id-token: write` and nothing else.
- No publishing from a branch. The tag check exists so the artifact has a name.
- No republishing a version. crates.io rejects it. If a publish fails after the
  upload was accepted, bump the patch version and release again.

## Failure modes

| Symptom | Cause |
| --- | --- |
| `version` job: tag does not match `vX.Y.Z` | The manifests and the tag disagree, or the five manifests disagree with each other. Delete the tag, fix, re-tag. |
| Publish job: OIDC exchange fails | A crate does not exist yet, or the trusted publisher does not match: wrong repository, wrong workflow filename, or an environment name that is set on one side and not the other. |
| Publish job: version already uploaded | The version was published before, usually by the manual first release. The job skips it; a real publish attempt is reported not as an error. |
| Publish job: `cargo publish` rejects the token | Trusted Publishing Only mode is on and the crate has no trusted publisher configured. |
| Dry-run step: `no matching package named ... found` | Expected for a crate whose sibling is not on the index yet. Only a sibling named in `packages.tsv` is tolerated; anything else fails the job. |
