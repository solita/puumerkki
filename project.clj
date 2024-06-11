(defproject puumerkki "0.9.3-SNAPSHOT"
  :description "Puumerkki allekirjoituskirjasto ja esimerkkipalvelin"
  :min-lein-version "2.9.1"
  :dependencies [[org.clojure/clojure "1.11.3"]
                 [pandect "0.6.1"] ;; SHA
                 ;[org.apache.pdfbox/pdfbox "1.8.17"] ;; no longer supported due to api changes required for 2.x
                 [org.apache.pdfbox/pdfbox "2.0.31"]
                 [org.bouncycastle/bcprov-jdk18on "1.78.1"]
                 [org.bouncycastle/bcmail-jdk18on "1.78.1"]
                 [commons-io "2.16.1"]
                 [commons-codec "1.8"]]

  :source-paths ["src/clj" "src/cljc"]
  :test-paths ["test/clj" "test/cljc"]
  :resource-paths []
  :aot :all
  :profiles {:dev {:dependencies [;; for internal test server
                                  [clj-kondo/clj-kondo "RELEASE"]
                                  [ring/ring "1.12.1"]
                                  [ring/ring-core "1.6.3"]
                                  [ring/ring-defaults "0.3.2"]
                                  [hiccup "1.0.5"]
                                  [clj-http "0.7.7"]
                                  [ring/ring-jetty-adapter "1.6.3"]
                                  [org.clojure/data.json "1.0.0"]]
                   :source-paths ["dev-src/clj"]
                   :resource-paths ["res" "pdf"]
                   :main puumerkki.main}})
