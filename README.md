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

## Publishing
### Snapshots
Snapshots are published to Clojars automatically by GitHub Actions when a commit is pushed to master.

### Releases
Releases are published to Clojars manually by developers. 

#### Prerequisites
1. Create a Clojars account 
1. Get verified on Clojars group by following the instructions [here](https://clojars.org/verify/group).
1. Create a deploy token by following instructions [in the wiki](https://github.com/clojars/clojars-web/wiki/Deploy-Tokens).
1. Optionally set `CLOJARS_USERNAME` and `CLOJARS_TOKEN` or answer interactive prompts when releasing.

#### Release
1. Switch to a new branch:\
`git switch -c release`\
1. Run one of the options. Use major when making breaking changes:\
`lein release :patch`, `lein release :minor`, or `lein release :major`\
1. Push the changes:\
`git push --follow-tags`\
1. Create a pull request and merge it to master.
