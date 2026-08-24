# Running spamassassin_make_test.yml locally with `act`

[`act`](https://github.com/nektos/act) runs GitHub Actions workflows locally in Docker, so you can test
`.github/workflows/spamassassin_make_test.yml` without pushing to GitHub.

## Files

Copy each `.dist` template to drop the `.dist` suffix, then edit as needed:

```bash
cp .github/act/act-event.json.dist .github/act/act-event.json
cp .github/act/act.env.dist .github/act/act.env
```

- `act-event.json` — the `workflow_dispatch` event payload. Set `inputs.runners`, `inputs.perls`,
  `inputs.database` (each a JSON-encoded string, matching the workflow's own input defaults) to pick
  which OS/perl/database combinations to run, and `inputs.tests` to a `t/*.t` glob to restrict which
  tests run.
- `act.env` — environment variables passed into the job containers, e.g. `PERL_MM_USE_DEFAULT=1`.

## Run

```bash
# dry run — show what would execute without running it
act -n -e .github/act/act-event.json --env-file .github/act/act.env

# real run
act -e .github/act/act-event.json --env-file .github/act/act.env
```
