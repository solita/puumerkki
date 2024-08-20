# Puumerkki
![NVD status](https://github.com/solita/puumerkki/actions/workflows/nvd.yml/badge.svg)
[![Clojars Project](https://img.shields.io/clojars/v/io.github.solita/puumerkki.svg)](https://clojars.org/io.github.solita/puumerkki)

Puumerkki is a library used for signing PDF documents. It can read and modify pdfs to prepare them for signing, calculate the hash for signing, create the signature container and embed it to the pdf. Signing is done by an external service, usually with an ID card from DVV together with a card reader and its software.

## Usage

See [`dev-src/clj/puumerkki/main.clj`](dev-src/clj/puumerkki/main.clj) for example usages

Energiatodistuspalvelu uses this library. Check out the code from [energiatodistus-pdf namespace](https://github.com/solita/ara-etp/blob/main/etp-core/etp-backend/src/main/clj/solita/etp/service/energiatodistus_pdf.clj)

## Testing

In order to execute tests in JVM, install Leigingen and run:

```
lein test
```

JS-tests are run with Shadow-cljs. Install npm, run `npm install` and execute tests:
```
npm test
```

## Test server
There is a test server, that can be used as an example when developing signature solutions. 

The server can be used to sign certificates together with the card reader software.

### Prerequisites
1. Install the card reader software <https://dvv.fi/en/card-reader-software>
1. Visit <https://localhost:53952/> and accept non-trusted certificate.
1. Download root certificates of citizen certificates from DVV by running:\
`./download-dvv-trusted-certificates.sh`
 
### Running the server
1. Start the server:\
`lein with-profile dev run -t citizen-certificate-roots.pem`
1. Start a reverse proxy to serve the content over https:\
On macOS and on Windows (not tested):\
`docker run -p 443:443 caddy caddy reverse-proxy --from localhost:443 --to http://host.docker.internal:3000`\
On Linux (not tested):\
`docker run -p 443:443 caddy caddy reverse-proxy --from localhost:443 --to http://localhost:3000`
1. Access the server at <https://localhost>. Accept the self-signed certificate.

## Publishing
### Snapshots
Snapshots are published to Clojars automatically by GitHub Actions when a commit is pushed to master.

### Releases
Releases are published to Clojars manually by developers. 

#### Prerequisites
1. Create a Clojars account 
1. Get verified on Clojars group by following the instructions [here](https://clojars.org/verify/group).
1. Create a deploy token by following instructions [in the wiki](https://github.com/clojars/clojars-web/wiki/Deploy-Tokens).
1. Set `CLOJARS_USERNAME` and `CLOJARS_TOKEN` environment variables.

#### Release
There are three release tasks to choose from: `release-current`, `release-minor`, and `release-major`.
The first one promotes the current snapshot to a release, and the other two increment the version number accordingly before doing the same.
After the release, a new snapshot version with patch number incremented is set. 

> **_NOTE:_**
> Why not use the default Leiningen release task or set desired :release-tasks in project.clj?
> 
> Version should be incremented after releasing, so that new snapshots have a new version.
> However, it's not known at the time of releasing whether the next release requires incrementing minor or major version. The current assumption is that most of the time patch release is enough. Therefore, patch version is incremented after releasing, and minor/major version is incremented only when needed when creating a new release. With the default tasks this wouldn't be possible, as every other patch would be skipped if version was incremented every time before release.

To release a new version, follow these steps:
1. Switch to a new branch:\
`git switch -c release`
1. Update `CHANGELOG.md`. Commit your changes.
1. Check whether there are any changes after the last release that warrant incrementing either minor (new features) or major (breaking changes) version.
Choose release task accordingly and run it:\
`lein release-current`, `lein release-minor`, or `lein release-major`
1. Push the branch with tags:\
`git push --follow-tags --set-upstream origin release`
1. Create a pull request and merge it to master.
