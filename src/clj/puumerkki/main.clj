(ns puumerkki.main
   (:require
      [puumerkki.codec :as codec]
      [puumerkki.pdf :as pdf]
      [puumerkki.crypt :as crypt]
      [pandect.algo.sha256 :refer :all]
      [ring.adapter.jetty :as jetty]
      [ring.middleware.params :as params]            ;; query string & body params
      [ring.middleware.multipart-params :as mparams] ;; post body
      [ring.middleware.cookies :as rookies]
      [hiccup.core :refer [html]]
      [clj-http.client :as http]
      [clojure.data.json :as json])

   (:import
      [org.apache.pdfbox.pdmodel.interactive.digitalsignature PDSignature SignatureInterface]
      [org.apache.pdfbox.pdmodel PDDocument]
      ;[org.apache.pdfbox.pdmodel.graphics.xobject PDPixelMap PDXObject PDJpeg]
      [org.apache.pdfbox.io RandomAccessFile]
      [org.apache.commons.io IOUtils]
      (org.apache.pdfbox.cos COSName)
      (java.security MessageDigest)
      [java.util Calendar]
      [java.io File FileInputStream FileOutputStream ByteArrayOutputStream]
      (org.apache.commons.codec.digest DigestUtils))

   (:gen-class))


;;
;; A minimal test server
;;

(defonce auth-secret (atom nil))

(defonce trust-roots (atom nil))

(defn load-trust-roots! [pem-path]
   (reset! trust-roots
      (crypt/load-trust-roots pem-path)))

(def origin "https://localhost")

(defn authentication-hash [data]
   (sha256-bytes data))

(def auth-payload "8fe85f31aa6fa5ff4e5cb7d03497e9a78c0f8492ec2da21279adedbc312976cf")

(def app-js
   (slurp "res/app.js"))

(def app-css
   (slurp "res/app.css"))

(defn cert-givenname [cert]
   (let [node
         (codec/asn1-find cert
            [:sequence [:identifier 2 5 4 4] :printable-string])]
      (if node
         (-> node (nth 2) (nth 1))
         nil)))

(defn cert-surname [cert]
   (let [node
         (codec/asn1-find cert
            [:sequence [:identifier 2 5 4 42] :printable-string])]
      (if node
         (-> node (nth 2) (nth 1))
         nil)))

(defn log-halko [& what]
   (future
      (println "Log: " what)
      ;(http/post "http://localhost:3001/log"
      ;   {:form-params {:service "puumerkki" :msg (apply str what)}})
      ))

(defn fold [o s l]
   (if (empty? l)
      s
      (o (first l)
         (fold o s (rest l)))))

(defn remove [filter seq]
   (fold
      (fn [elem tail]
         (if (filter elem)
            tail
            (cons elem tail)))
      nil seq))

; (pdf/add-watermarked-signature-space "pdf/testi.pdf" "pdf/testi.pdf-signable" "Stephen Signer" "pdf/stamp.jpeg" 100 300)

;; micro authorization

(defn signer->authorized-user [signer]
   {:name (str (:givenname signer) " " (:surname signer))
    :id 42
    :roles ["user" "admin"]})

;; micro session management

(def session-timeout-seconds 30)

(defn posix-time []
   (quot (System/currentTimeMillis) 1000))


(defn sign-cookie-map [cookie-map]
   (let [data (json/write-str cookie-map)]
      (str (crypt/hmac-sign @auth-secret data) "," data)))

;; user cookie has expiration + signature
(defn signer->user-cookie [signer]
   (sign-cookie-map
      (-> (signer->authorized-user signer)
         (assoc :expires
            (+ (posix-time) session-timeout-seconds)))))

(defn user-cookie->user-map [cookie]
   (let [[_ hmac data] (re-find #"^([0-9a-f]+),(.*)" (or (:value cookie) ""))]
      ;; temporal hardening and renewal here later
      (if (and hmac data
               (= hmac (crypt/hmac-sign @auth-secret data)))
         (let [map (json/read-str data :key-fn keyword)
               now (posix-time)]
            (cond
               (< (:expires map) now)
                  nil
               :else
                  map))
         nil)))

(defn wrap-user-data [handler]
   (fn [req]
      (if-let [user-map (user-cookie->user-map (get (:cookies req) "puumerkki"))]
         (handler (assoc req :puumerkki user-map))
         (handler req))))

(def http-ok 200)
(def http-ok-no-content 204)

(defn router [req]
   (try
   (log-halko "req <- " (:uri req))

   (cond

      ;; PDF part

      (= "/sign" (:uri req))
         (let [data (json/read-str (:body req) :key-fn keyword)]
            (log-halko "signing")
            (if-let
               [errs
                  (remove
                     ;; test cards currently not valid (expired)
                     (partial = :cert-not-valid)
                     (crypt/validation-errors
                        @trust-roots
                        (:signature data)
                        (byte-array
                           (codec/base64-decode-octets (:content (:request data))))
                        (:chain data)))]
               (do
                  (log-halko "PDF signature failure: " errs)
                  {:status 400
                   :headers {"Content-Type" "text/plain"}
                   :body (str "Invalid signature: " errs)})
               (let [pdf-data
                        (pdf/read-file "pdf/testi.pdf-signable")
                     pkcs7 (pdf/make-pkcs7 data pdf-data)]
                  ;; crossvalidate pdf with signature later
                  (log-halko "PDF PKCS done")
                  (pdf/write-file! "pdf/test-allekirjoitettu.pdf"
                     (pdf/write-signature! pdf-data pkcs7))
                  {:status 200
                   :headers {"Content-Type" "text/plain"}
                   :body "OK"})))

      (= "/verify" (:uri req))
         (let [pdf-data (pdf/read-file "pdf/test-allekirjoitettu.pdf")
               sigp (pdf/cursory-verify-signature pdf-data)]
            (log-halko (if sigp "/verify OK" "/verify FAILED"))
            (if sigp
               {:status 200
                :headers {"Content-Type" "text/plain"}
                :body
                   (str "OK: <div>"
                      (with-out-str
                         ; (clojure.pprint/pprint sigp)
                         (println sigp)
                         )
                      "</div>")
               }
               {:status 300
                :headers {"Content-Type" "text/plain"}
                :body "Virhe."}))

      (= "/pre-sign" (:uri req))
         (let [req (json/read-str (:body req) :key-fn keyword)
               preparation-res  ;; construct the signable version
                  (pdf/add-watermarked-signature-space
                     "pdf/testi.pdf"
                     "pdf/testi.pdf-signable-x"
                     "Stephen Signer"
                     "pdf/stamp.jpeg"
                     100 300)]
            (if preparation-res
               (let [pdf-data
                        (pdf/read-file "pdf/testi.pdf-signable")
                        ; (pdf/read-file "pdf/testi.pdf")

                     request (crypt/pdf-sign-request (get req :version {}) pdf-data)]
                  ;; pdf signature request does not need to be signed, because
                  ;; validating it involves recomputing and validating the hash
                  ;; of the document to be signed
                  (log-halko "PDF signing preparation request for " (:version req))
                  {:status 200
                   :headers {"Content-Type" "application/json"}
                   :body request})
               {:status 500
                :body "This PDF cannot be signed."}))

      ;; Authentication

      (= "/authenticate" (:uri req))
         (let [data (json/read-str (:body req) :key-fn keyword)
               challenge (-> data (get :signedData) (get :content)
                           codec/base64-decode)]

            (let [signer (and data (crypt/verify-authentication-challenge @trust-roots @auth-secret data challenge auth-payload))]
               (if signer
                  (let [user-token (signer->user-cookie signer)]
                     (log-halko (if signer "/authenticate OK" "/authenticate FAILED"))
                     (log-halko signer)
                     {:status 200
                      :headers {"Content-Type" "text/plain"}
                      :cookies
                         {"puumerkki" {:value user-token
                                       :secure true
                                       :http-only true
                                       :same-site :strict}}
                      :body (json/write-str (signer->authorized-user signer))})
                  (do
                     (log-halko "/authenticate failed")
                     {:status 300
                      :headers {"Content-Type" "text/plain"}
                      :body "No"}))))

      (= "/auth-challenge" (:uri req))
         (let [req (json/read-str (:body req) :key-fn keyword)]
            (log-halko "fetching authentication challenge: " req)
            (let [request (crypt/digisign-authentication-request
                               @auth-secret
                               (get req :host "localhost")
                               (get req :version {})
                               auth-payload)]
               (log-halko request)
               {:status 200
                :headers {"Content-Type" "application/json"}
                :body request}))

      (= "/session" (:uri req))
         (if-let [info (get req :puumerkki)]
            {:status http-ok
             :headers {"Content-type" "application/json"}
             :body (json/write-str info)}
            {:status http-ok-no-content
             :body "no session"})

      ;; Meta

      (= "/load-cas" (:uri req))
         (do
            (log-halko "loading trust roots")
            (load-trust-roots! "trust-roots.pem")
            {:status 200
             :headers {"Content-Type" "text/html"}
             :body
                (str "<ul>"
                   (reduce
                      (fn [tail cert]
                         (str "<li>" (crypt/cert-name cert) tail))
                      "</ul>"
                      @trust-roots))})


      ;; Test page

      ;; header, top of page
      ;; page, page main content
      ;; *box, inline areas
      :else
         {:status 200
          :body
             (html
                [:html
                   [:head
                      [:title "Puumerkki"]
                      [:meta {:charset "UTF-8"}]]
                      [:script app-js]
                      [:style app-css]
                   [:body {:onload "main()"}

                      [:div {:class "header" :id "header"}
                         [:b [:a {:onclick "navigateLink(\"etusivu\")" :href "etusivu" :class "tablink"}
                            "Puumerkki"]]
                         " "
                         [:a {:onclick "navigateLink(\"pdf\")" :href "pdf" :class "tablink"}
                            "PDF"]
                         " "
                         [:a {:onclick "navigateLink(\"tyokalut\")" :href "tyokalut" :class "tablink"}
                            "Työkalut"]
                         " "
                         [:div {:class "loginbox" :id "loginbox"}
                            [:a {:onclick "navigateLink(\"tunnistautuminen\")" :href "tunnistautuminen" :class "tablink"}
                               "&#x1F464;"]]]

                      [:div {:class "page" :id "page"}

                         [:div {:class "etusivu" :id "etusivu"}
                            [:h1 "Etusivu"]]

                         [:div {:class "tunnistautuminen" :id "tunnistautuminen"}
                            [:h1 "Tunnistautuminen"]

                            [:p "Tunnistautuminen: "
                               [:button {:onClick "startAuthentication()"}
                               "tunnistaudu"]]
                            [:div {:id "authentication" :class "result" :onClick "clearMe(this)"} ""]

                            ]

                         [:div {:class "pdf" :id "pdf"}

                            [:h1 "PDF Allekirjoitus"]

                            [:p "Allekirjoita: "
                               [:button {:onClick "startSigning('signature')"}
                               "allekirjoita"]]
                            [:div {:id "signature" :class "result" :onClick "clearMe(this)"} ""]]


                         [:div {:class "tyokalut" :id "tyokalut"}
                            [:h1 "Työkalut"]

                            [:p "Digisign version haku: "
                               [:button {:onClick "getVersion('mpollux', false)"}
                               "hae"]]
                            [:div {:id "mpollux" :class "result" :onClick "clearMe(this)"} ""]

                            [:p "Varmenteet: "
                               [:button {:onClick "loadCAs()"}
                               "lataa"]]
                            [:div {:id "cas" :class "result" :onClick "clearMe(this)"} ""]

                            [:p "Revokaatio: "
                               [:button {:onClick "loadRevocation()"}
                               "päivitä"]]
                            [:div {:id "cas" :class "result" :onClick "clearMe(this)"} ""]]]


                      ]])})
   (catch Exception e
      (log-halko "ERROR: " e)
      {:status 500
       :body "fail"})))

(defn wrap-default-content-type [handler]
   (fn [req]
      (let [response (handler req)]
         (if (get-in response [:headers "Content-Type"])
            response
            (assoc-in response [:headers "Content-Type"] "text/html")))))

(defn wrap-body-string [handler]
  (fn [request]
      (let [body-str (ring.util.request/body-string request)]
         (handler (assoc request :body body-str)))))

(defn wrap-error-scrubber [handler]
   (fn [request]
      (try (handler request)
          (catch Exception e
             (log-halko "Exception: " e)
             {:status 500
              :body "An error occurred."}))))


(def app
   (->
      router
      (wrap-user-data)
      (mparams/wrap-multipart-params)
      (rookies/wrap-cookies)
      (wrap-body-string) ;; use :params instead
      ;(params/wrap-params)
      (wrap-default-content-type)
      (wrap-error-scrubber)
      ))

(def default-opts
   {:port 3000
    :join? false
    :host "localhost"                 ;; where to accept connections from
    :trust-roots "trust-roots.pem"    ;; accepted roots for signatures & authentication
    :hmac-secret "randomized"         ;; authentication challenge signing secret
    })

(defn start [opts]
   ;; possibly move out of crypt
   (load-trust-roots!
      (get opts :trust-roots))
   (reset! auth-secret
      (get opts :hmac-secret))
   (log-halko "starting up")
   (if @trust-roots
      (jetty/run-jetty #'app
         (select-keys opts [:port :join? :host]))
      (println "Cannot start demo app: no trust roots")))

(defn go []
   (start default-opts))

(defn handle-args [opts args]
   (cond
      (empty? args)
         (start opts)
      (contains? #{"-r" "--allow-remote-access"} (first args))
         ;; allow access from hosts other than localhost
         (handle-args (dissoc opts :host) (rest args))
      (contains? #{"-h" "--help"} (first args))
         (do
            (println "Usage: java -jar puumerkki.jar [-h] [-t|--trust-roots <pemfile>]")
            0)
      (and (contains? #{"-t" "--trust-roost"} (first args)) (not (empty? (rest args))))
         (handle-args (assoc opts :trust-roots (nth args 1))
                      (rest (rest args)))
      (and (contains? #{"-s" "--secret"} (first args)) (not (empty? (rest args))))
         (handle-args (assoc opts :hmac-secret (nth args 1))
                      (rest (rest args)))
      :else
         (do
            (println "Invalid arguments: " args ". Use -h for help.")
            nil)))

(defn -main [& args]
   (try
      (handle-args default-opts args)
      (catch Exception e
         (log-halko "ERROR: " e)
         1)))

