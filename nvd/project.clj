(defproject nvd-helper "local"
            :description "nvd-clojure helper project"
            :dependencies [[nvd-clojure "4.0.0"
                            ;; Replaced by a newer version until NVD-Clojure is updated
                            :exclusions [org.owasp/dependency-check-core]]
                           [org.owasp/dependency-check-core "10.0.3"]
                           ;; Dependency-check-core brings in older version which doesn't work
                           [org.slf4j/slf4j-api "2.0.16"]
                           [org.clojure/clojure "1.12.0"]]
            :jvm-opts ["-Dclojure.main.report=stderr"])
