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
     (javax.crypto Mac)
     (javax.crypto.spec SecretKeySpec)
     (sun.security.x509 CRLDistributionPointsExtension)
     ))

(def hmac-type "HMACSHA256")

(defn hmac-sign [key-pass string]
   (apply str
      (map (fn [x] (format "%x" x))
         (let [mac (Mac/getInstance hmac-type)
               key (SecretKeySpec. (.getBytes key-pass) (.getAlgorithm mac))]
            (->
               (doto mac
                  (.init key)
                  (.update (.getBytes string)))
               .doFinal)))))

(def b64->bytes
   (comp byte-array
         codec/base64-decode-octets))

(defn bytes->cert [bytes]
   (try
      (let [cf (CertificateFactory/getInstance "X.509")]
          (.generateCertificate cf (io/input-stream bytes)))
      (catch Exception e
         nil)))

(defn read-cert [cf instr]
   (if (.available instr)
      (try
         (.generateCertificate cf instr)
         (catch Exception e
            nil))
      nil))

(defn pem-file->certs [path]
   (try
      (let [stream (io/input-stream path)
            cf (CertificateFactory/getInstance "X.509")]
         (loop [certs nil]
            (let [cert (read-cert cf stream)]
               (if cert
                  (recur (cons cert certs))
                  certs))))
      (catch Exception e
         false)))

(defn cert-name [cert]
   (try
      (.getName (.getSubjectDN cert))
      (catch Exception e
         "(bad cert)")))

(defn trusted-root-cert? [roots cert]
   (reduce
      (fn [is ca]
         (or is (.equals ca cert)))
      false roots))

;; -> list | false on error
(def load-trust-roots
   pem-file->certs)

(defn string->bytes [s]
   (.getBytes s))

(def b64->cert
   (comp bytes->cert
         b64->bytes))

(def chain->signing-cert
   (comp b64->cert first))

(defn cert->pubkey [cert]
   (if cert (.getPublicKey cert)))

(defn signature-validity [errs pub signature type data]
   (let [verifier (Signature/getInstance type)]   ; <- type requested by us
      (.initVerify verifier pub)
      (.update verifier data)
      (if (.verify verifier signature)
         errs
         (cons :signature-not-valid errs))))

(defn b64-cert->pem [b]
   (str "-----BEGIN CERTIFICATE-----\n"
      (clojure.string/replace b #"([^\n]{80})" "$1\n") ;; for readability
      "\n-----END CERTIFICATE-----\n"))

(defn anchor-cert-validity [errs roots b64cert]
   (let [cert (b64->cert b64cert)]
      (if (trusted-root-cert? roots cert)
         errs
         (cons :untrusted-root-cert errs))))

(defn chain-validity [errs certs]
   (cond
      (nil? certs)
         (cons :invalid-certificate-chain errs)
      (empty? (rest certs))
         errs ;; root cert is checked elsewhere
      :else
         (let [sub (first certs)       ;; the chain is complete and in order
               issuer (second certs)]
            (try
               (do
                  (.verify sub (cert->pubkey issuer))
                  (chain-validity errs (rest certs)))
               (catch Exception e
                  ;; could accidentally leak sensitive data to log if this is e.g. the signing
                  ;; certificate and error results from card reader application failure or
                  ;; unexpected change in its operation.
                  ; (println "ERROR: certificate chain validation failed for certificate: " sub)
                  (cons :invalid-certificate-chain errs))))))

;; exception -> boolean
(defn cert-validity [errs cert]
   (try
      (.checkValidity cert)
      errs
      (catch Exception e
         ; (cons :cert-not-valid errs)
         ;; need to order new test cards
         ; (println "WARNING: certificate not currently valid, but allowing it while testing")
         errs)))

(defn cert-revocation-status [errs cert]
   (println "WARNING: No CRL/OCSP handling yet.")
   errs)

;; -> nil = ok, list of error symbols otherwise
(defn validation-errors [roots sig-b64s msg-bytes chain]
   (try
      (let [cert (chain->signing-cert chain)
            pub  (cert->pubkey cert)]
         (cond
            (not cert)
               (list :cannot-read-certificate)
            (not pub)
               (list :cannot-read-public-key)
            :else
               (-> nil
                  (cert-validity cert)          ;; validity time, relies on computer clock
                  (cert-revocation-status cert) ;; CRL distribution point known, no loading and check yet
                  (signature-validity pub (b64->bytes sig-b64s) "SHA256withRSA" msg-bytes)
                  (chain-validity (map b64->cert chain))
                  (anchor-cert-validity roots (last chain))
                  )))
      (catch Exception e
         (list :validationerror))))

;; You probably want to call validation-errors instead to be able to log/report the reasons
(defn valid? [roots sig-b64s msg-string chain]
   (let [errs (validation-errors roots sig-b64s (string->bytes msg-string) chain)]
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
         ; (println "ERROR: failed to find CRL source from cert " (cert-name cert))
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
    :key-size (rsa-key-size (.getPublicKey cert))     ; nil for non-rsa (EC)
    :crl-points (crl-distribution-points cert)
    })

;; -> nil if signature is invalid | map of signing certificate information
(defn signer-info [roots sig-b64s msg-string chain]
   (let [errs (validation-errors roots sig-b64s (string->bytes msg-string) chain)]
      (if (empty? errs)
         (cert->signer-info
            (chain->signing-cert chain))
         false)))

;; a variable data is usually a hash of the data/document/event.
;; host prefix is added later.
(defn authentication-challenge [secret variable-data]
      (let [now (System/currentTimeMillis)
            timestamped-data (str now "\n" variable-data)
            signature (hmac-sign secret timestamped-data)]
         (str signature "\n" timestamped-data)))

(defn digisign-authentication-challenge [secret host version variable-data]
   (if-let [data (authentication-challenge secret variable-data)]
      (codec/base64-encode
         (str "https://" host "\n" data))))

;; -> json in a string | false if unsupported version/algorithm combination
(defn digisign-authentication-request [secret host version variable-data]
   (let [challenge (digisign-authentication-challenge secret host version variable-data)]
      ;; future version-specific handling here later
      (str
        "{\"selector\":{\"keyusages\":[\"digitalsignature\"]},
          \"content\":\"" challenge "\",
          \"contentType\":\"data\",
          \"hashAlgorithm\":\"SHA256\",
          \"signatureType\":\"signature\",
          \"version\":\"1.1\"}")))

(defn verify-authentication-challenge [roots secret signature challenge maybe-payload]
   (let [[_ hmac timestamp data] (re-find #"^https://[^\n]+\n([0-9a-f]+)\n([0-9]+)\n(.*)" challenge)]
      (cond
         ;; valid authentication challenge signature?
         (not (= hmac (hmac-sign secret (str timestamp "\n" data))))
            false
         ;; if a known specific payload is used, is it equal to the one in challenge?
         (not (= data (or maybe-payload data)))
            false
         ;; valid authentication challenge timeout? (currently not needed)
         :else
            (signer-info roots (:signature signature) challenge (:chain signature)))))

