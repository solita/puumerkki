(defproject puumerkki "1.0"
  :description "Puumerkki allekirjoituskirjasto ja esimerkki"
  :min-lein-version "2.9.1"
  :dependencies [[org.clojure/clojure "1.10.1"]
                 [org.clojure/data.json "1.0.0"]
                 ;[metosin/compojure-api "1.2.0-20161028.114958-3"]
                 ;[metosin/ring-swagger "0.22.11"]
                 [ring/ring "1.7.1"]
                 [pandect "0.6.1"] ;; SHA
                 [ring/ring-defaults "0.3.2"]
                 ;[org.apache.pdfbox/pdfbox "1.8.16"]
                 [org.apache.pdfbox/pdfbox "2.0.19"]
               
                 ;; for internal test server 
                 [ring/ring-core "1.6.3"]
                 [hiccup "1.0.5"]
                 [ring/ring-jetty-adapter "1.6.3"]
                 [org.clojure/data.json "1.0.0"]]

  :source-paths ["src/clj" "src/cljc"]
  :test-paths ["test"]
  :resource-paths []

  :main puumerkki.main
)

