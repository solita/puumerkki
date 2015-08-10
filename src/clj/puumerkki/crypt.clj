(ns puumerkki.crypt
  (:require
     [puumerkki.codec :as codec]
     [clojure.java.io :as io])

  (:import
     (java.security MessageDigest)
     (java.security Signature)
     (java.security.spec X509EncodedKeySpec)
     (java.security.spec PKCS8EncodedKeySpec)
     (java.security KeyFactory)
     (java.security.cert CertificateFactory)
     ))

;; signing cert
(defn chain->cert [chain]
   (try
      (let [cert-str (first chain)
            cert-bytes (byte-array (codec/base64-decode-octets cert-str))
            cf (CertificateFactory/getInstance "X.509")]
          (.generateCertificate cf (io/input-stream cert-bytes)))
      (catch Exception e
         ; (println "ERROR: chain->cert: " e)
         false)))

(defn cert->pubkey [cert]
   (if cert (.getPublicKey cert)))

(defn chain->pubkey [chain]
   (if-let [cert (chain->cert chain)]
      (cert->pubkey cert)))

(defn signature-validity [errs pub sig-s data]
   (let [verifier (Signature/getInstance "SHA256withRSA")   ; <- type requested by us
         signature (byte-array (codec/base64-decode-octets sig-s))]
      (.initVerify verifier pub)
      (.update verifier (.getBytes data))
      (if (.verify verifier signature)
         errs
         (cons :signature-not-valid errs))))

;; exception -> boolean
(defn cert-validity [errs cert]
   (try
      (.checkValidity cert)
      errs
      (catch Exception e
         (cons :cert-not-valid errs))))

;; partial version
(defn validation-errors [sig-b64s msg-string chain]
   (let [cert (chain->cert chain)
         pub  (cert->pubkey cert)]
      (cond
         (not cert)
            (list :cannot-read-certificate)
         (not pub)
            (list :cannot-read-public-key)
         :else
            (-> nil
               (cert-validity cert)
               (signature-validity pub sig-b64s msg-string)))))

;; You probably want to call validation errors instead to be able to log/report the reasons
(defn valid? [sig-b64s msg-string chain]
   (let [errs (validation-errors sig-b64s msg-string chain)]
      (if (empty? errs)
         true
         (do
            false))))

(defn n-bits [num]
   (loop [n 0 h 1]
      (if (> h num)
         n
         (recur (+ n 1) (*' 2 h)))))

;; get bit count if applicable
(defn rsa-key-size [pub]
   (try
      (n-bits (.getModulus pub))
      (catch Exception e
         (print "fail: " e)
         nil)))

(defn cert->signer-info [cert]
   {:serial (.getSerialNumber cert)
    :issuer (.getName (.getIssuerDN cert))
    :not-after (.getNotAfter cert)
    :not-before (.getNotBefore cert)
    :givenname (.getGivenName (.getSubjectDN cert))
    :surname (.getGivenName (.getSubjectDN cert))
    :commonname (.getCommonName (.getSubjectDN cert))
    :algorithm (.getAlgorithm (.getPublicKey cert))
    :key-size (rsa-key-size (.getPublicKey cert))     ; nil for non-rsa
    })

;; -> nil if signature is invalid | map of signing certificate information
(defn signer-info [sig-b64s msg-string chain]
   (let [errs (validation-errors sig-b64s msg-string chain)]
      (if (empty? errs)
         (cert->signer-info
            (chain->cert chain))
         (do
            (println "ERRORS: " errs)
            nil))))



