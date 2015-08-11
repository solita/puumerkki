(ns puumerkki.crypt
  (:require
     [puumerkki.codec :as codec]
     [clojure.java.io :as io]
     [clojure.string :as str])

  (:import
     (java.security MessageDigest)
     (java.security Signature)
     (java.security.spec X509EncodedKeySpec)
     (java.security.spec PKCS8EncodedKeySpec)
     (java.security KeyFactory)
     (java.security.cert CertificateFactory)
     (sun.security.x509 CRLDistributionPointsExtension)
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
               (signature-validity pub sig-b64s msg-string)
               ; trust chain
               ; revocation via crl/ocsp
               ))))

;; You probably want to call validation errors instead to be able to log/report the reasons
(defn valid? [sig-b64s msg-string chain]
   (let [errs (validation-errors sig-b64s msg-string chain)]
      (empty? errs)))

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
         nil)))

(defn cert-crl-bytes [cert]
   (try
      (nth
         (codec/asn1-decode
            (map
               (fn [x] (bit-and 255 x))
               (seq (.getExtensionValue cert "2.5.29.31"))))
         1)
      (catch Exception e
         (println "ERROR: failed to find CRL source from cert with serial" (.getSerialNumber cert))
         nil)))

(defn crl-distribution-points [cert]
   (map
      (fn [crl]
         (let [s (.toString (.names (.getFullName crl)))]
            (str/replace s #"^\[URIName: (.*)\]$" "$1")))
      (.get (.getCRLDistributionPointsExtension cert)
         CRLDistributionPointsExtension/POINTS)))

(defn cert->signer-info [cert]
   {:serial (.getSerialNumber cert)
    :issuer (.getName (.getIssuerDN cert))
    :not-after (.getTime (.getNotAfter cert))
    :not-before (.getTime (.getNotBefore cert))
    :givenname (.getGivenName (.getSubjectDN cert))
    :surname (.getGivenName (.getSubjectDN cert))
    :commonname (.getCommonName (.getSubjectDN cert))
    :algorithm (.getAlgorithm (.getPublicKey cert))
    :key-size (rsa-key-size (.getPublicKey cert))     ; nil for non-rsa
    :crl-points (crl-distribution-points cert)
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



