(defproject puumerkki "0.9.2"
  :description "Puumerkki allekirjoituskirjasto ja esimerkkipalvelin"
  :min-lein-version "2.9.1"
  :dependencies [[org.clojure/clojure "1.10.1"]
                 [pandect "0.6.1"] ;; SHA
                 ;[org.apache.pdfbox/pdfbox "1.8.16"] ;; no longer supported due to api changes required for 2.x
                 [org.apache.pdfbox/pdfbox "2.0.19"]
                 [org.bouncycastle/bcprov-jdk15on "1.65"]
                 [org.bouncycastle/bcmail-jdk15on "1.65"]

                 ;; for internal test server
                 [ring/ring "1.7.1"]
                 [ring/ring-core "1.6.3"]
                 [ring/ring-defaults "0.3.2"]
                 [hiccup "1.0.5"]
                 [ring/ring-jetty-adapter "1.6.3"]
                 [org.clojure/data.json "1.0.0"]]

  :source-paths ["src/clj" "src/cljc"]
  :test-paths ["test"]
  :resource-paths []
  :aot :all

  :main puumerkki.main
)

