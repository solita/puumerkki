(defproject io.github.solita/puumerkki "0.12.1-SNAPSHOT"
  :license {:name "Eclipse Public License"
            :url  "http://www.eclipse.org/legal/epl-v10.html"}
  :url "https://github.com/solita/puumerkki"
  :description "Puumerkki allekirjoituskirjasto ja esimerkkipalvelin"
  :min-lein-version "2.9.1"
  :dependencies [[org.clojure/clojure "1.12.0"]
                 [pandect "1.0.2"]                          ;; SHA
                 ;[org.apache.pdfbox/pdfbox "1.8.17"] ;; no longer supported due to api changes required for 2.x
                 [org.apache.pdfbox/pdfbox "2.0.32"]
                 [org.bouncycastle/bcprov-jdk18on "1.78.1"]
                 [org.bouncycastle/bcmail-jdk18on "1.78.1"]
                 [commons-io "2.16.1"]
                 [commons-codec "1.17.1"]]
  :aliases {"release-major"   ["do"
                               ["vcs" "assert-committed"]
                               ["change" "version" "leiningen.release/bump-version" "major"]
                               ["vcs" "commit"]
                               ["release"]]
            "release-minor"   ["do"
                               ["vcs" "assert-committed"]
                               ["change" "version" "leiningen.release/bump-version" "minor"]
                               ["vcs" "commit"]
                               ["release"]]
            "release-current" [["release"]]}
  :release-tasks [["vcs" "assert-committed"]
                  ["change" "version" "leiningen.release/bump-version" "release"]
                  ["vcs" "commit"]
                  ["vcs" "tag" "--no-sign"]
                  ["deploy"]
                  ["change" "version" "leiningen.release/bump-version" "patch"]
                  ["vcs" "commit"]]
  :source-paths ["src/clj" "src/cljc"]
  :test-paths ["test/clj" "test/cljc"]
  :resource-paths []
  :aot :all
  :deploy-repositories [["releases" {:url           "https://clojars.org/repo"
                                     :username      :env/clojars_username
                                     :password      :env/clojars_token
                                     :sign-releases false}]
                        ["snapshots" {:url      "https://clojars.org/repo"
                                      :username :env/clojars_username
                                      :password :env/clojars_token}]]
  :profiles {:dev {:dependencies   [;; for internal test server
                                    [clj-kondo/clj-kondo "RELEASE"]
                                    [ring/ring "1.12.2"]
                                    [ring/ring-core "1.12.2"]
                                    [ring/ring-defaults "0.5.0"]
                                    [hiccup "1.0.5"]
                                    [clj-http "3.13.0"]
                                    [ring/ring-jetty-adapter "1.12.2"]
                                    [org.clojure/data.json "2.5.0"]]
                   :source-paths   ["dev-src/clj"]
                   :resource-paths ["res" "pdf"]
                   :main           puumerkki.main}})
