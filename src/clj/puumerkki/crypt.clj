(ns puumerkki.crypt
  (:require
     [puumerkki.codec :as codec])

  (:import (java.security MessageDigest)))


(defn verify [signature chain]
   (println "puumerkki.crypt: verification stub called with " signature " and " chain)
   true)
