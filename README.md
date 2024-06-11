# Puumerkki
![NVD status](https://github.com/solita/puumerkki/actions/workflows/nvd.yml/badge.svg)

A library for communicating with DVV certificate card reader software

## Usage

See `dev-src/clj/puumerkki/main.clj` for example usages

## Testing

In order to execute tests in JVM, install Leigingen and run:

```
lein test
```

JS-tests are run with Shadow-cljs. Install npm, run `npm install` and execute tests:
```
npm test
```

## Releasing
Snapshots are published to Clojars automatically when a commit is pushed to master.

To release a new version, [create a token for clojars](https://github.com/clojars/clojars-web/wiki/Deploy-Tokens).

Optionally set `CLOJARS_USERNAME` and `CLOJARS_TOKEN` or answer interactive prompts when releasing.

Then switch to a new branch:\
`git switch -c release`\
Run:\
`lein release :patch`, `lein release :minor`, or `lein release :major`\
Push the changes:\
`git push --follow-tags`\
Create a pull request and merge it to master.
