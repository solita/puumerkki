(ns puumerkki.main
   (:require
      [puumerkki.codec :as codec]
      [puumerkki.pdf :as pdf]
      [puumerkki.crypt :as crypt]
      [pandect.algo.sha256 :refer :all]
      [ring.adapter.jetty :as jetty]
      [ring.middleware.params :as params]            ;; query string & body params
      [ring.middleware.multipart-params :as mparams] ;; post body
      [hiccup.core :refer [html]]
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

(def origin "https://localhost")

(pdf/add-watermarked-signature-space "pdf/testi.pdf" "pdf/testi.pdf-signable" "Stephen Signer" "pdf/stamp.jpeg" 100 300)

(def test-pdf-data (pdf/read-file "pdf/testi.pdf-signable"))      ;;
(def test-pdf-pkcs (pdf/compute-base64-pkcs test-pdf-data))       ;; to be sent to mpollux from https frontend

;; chosen by server
(def authentication-challenge-content "\n\nTime: 01-01-2001\nHash: sha256,b5bb9d8014a0f9b1d61e21e796d78dccdf1352f23cd32812f4850b878ae4944c\n")

(def full-authentication-challenge
   (str origin authentication-challenge-content))

(def authentication-challenge
   (codec/base64-encode
      full-authentication-challenge))

(defn authentication-hash [data]
   (sha256-bytes data))

(def js-code
(str "var pkcs = '" test-pdf-pkcs "';
var auth = '" authentication-challenge "';

var mpolluxInfo  = false;
var mpolluxUrl   = 'https://localhost:53952';
var signature    = false;
var authresponse = false;

function toSmallString(val) {
   let s = val + '';
   if (s.length > 100) {
      s = '<font size=-4>' + val + '</font>';
   }
   return s;
}

function renderObject(name,exp) {
   let info = name + ':<ul>';
   Object.keys(exp).forEach(function(key) {
      let val = exp[key];
      let rep;
      if (Array.isArray(val)) {
         rep = '<ol>';
         val.forEach(function(val) {
            rep += '<li>' + toSmallString(val);
         });
         rep += '</ol>';
      } else {
         rep = toSmallString(val);
      }
      info += '<li>' + key + ': ' + rep;
   });
   info += '</ul>'
   return info;
}

function spinner(target) {
   document.getElementById(target).innerHTML= '<div class=spinner><div>';
}

function getVersion() {
   var http = new XMLHttpRequest();
   http.open('GET', mpolluxUrl + '/version');
   http.setRequestHeader('Content-Type', 'application/json; charset=UTF-8');
   http.overrideMimeType('application/json'); // avoid xml parsing error due to missing mime

   http.onreadystatechange = function() {
     if (this.readyState == 4 && this.status == 200) {
        mpolluxInfo = JSON.parse(this.responseText);
        console.log(mpolluxInfo);
        document.getElementById('mpollux').innerHTML = renderObject('versiotiedot', mpolluxInfo);
     } else {
        console.log('status ' + this.readyState);
     }
   }
   http.onloadend = function () {};
   spinner('mpollux');
   http.send();
}

function loadCAs() {
   var http = new XMLHttpRequest();
   http.open('GET', '/load-cas');

   http.onreadystatechange = function() {
     if (this.readyState == 4 && this.status == 200) {
        document.getElementById('cas').innerHTML = this.responseText;
     } else {
        console.log('status ' + this.readyState);
     }
   }
   spinner('cas');
   http.send();
}

var sigtest = {'selector':{'keyusages':['nonrepudiation']},   //     'keyalgorithms': ['rsa']
               'content':pkcs,
               'contentType':'data',
               'hashAlgorithm':'SHA256',
               'signatureType':'signature',
               'version':'1.1'
             };

var authtest = {'selector':{'keyusages':['digitalsignature']},
                'content':auth,
                'contentType':'data',
                'hashAlgorithm':'SHA256',
                'signatureType':'signature',
                'version':'1.1'};


function getSignature() {
   if (!mpolluxInfo) {
      alert('hae ensin versiotiedot');
      return;
   }
   if (location.protocol !== 'https:') {
      alert('signature must be generated over https');
      return;
   }
   var http = new XMLHttpRequest();
   http.open('POST', mpolluxUrl + '/sign', true);
   http.setRequestHeader('Content-Type', 'application/json; charset=UTF-8');
   http.overrideMimeType('application/json'); // mpollux ei lähetä, tulee muuten xml parsintavirhe
   http.onreadystatechange = function() {
     if (this.readyState == 4 && this.status == 200) {
        signature = JSON.parse(this.responseText);
        document.getElementById('signature').innerHTML = renderObject('allekirjoitus', signature);

     } else {
        console.log('status ' + this.readyState);
     }
   }
   http.onloadend = function () {};
   console.log('Sending ' + JSON.stringify(sigtest));
   spinner('signature');
   http.send(JSON.stringify(sigtest));
}

function sendSignature() {
   if (!signature) {
      alert('tee ensin allekirjoitus');
      return;
   }
   var http = new XMLHttpRequest();
   http.open('POST', '/sign', true);
   http.setRequestHeader('Content-Type', 'application/json; charset=UTF-8');
   http.onreadystatechange = function() {
     if (this.readyState == 4 && this.status == 200) {
        document.getElementById('sent').innerHTML = 'ok';
     } else {
        document.getElementById('sent').innerHTML = 'failed';
     }
   }
   http.onloadend = function () {};
   spinner('sent');
   http.send(JSON.stringify(signature));
}

function verifySignature() {
   var http = new XMLHttpRequest();
   http.open('GET', '/verify', true);
   http.onreadystatechange = function() {
     if (this.readyState == 4 && this.status == 200) {
        document.getElementById('status').innerHTML = this.response;
     } else {
        document.getElementById('status').innerHTML = 'error';
     }
   }
   http.onloadend = function () {};
   spinner('status');
   http.send(JSON.stringify(signature));
}

function authenticate() {
   if (location.protocol !== \"https:\") {
      alert('must authenticate over https');
      return;
   }
   var http = new XMLHttpRequest();
   http.open('POST', mpolluxUrl + '/sign', true);
   http.setRequestHeader('Content-Type', 'application/json; charset=UTF-8');
   http.onreadystatechange = function() {
     if (this.readyState == 4 && this.status == 200) {
        authresponse = JSON.parse(this.responseText);
        if (authresponse.status == 'ok') {
           sendAuth();
        } else {
           document.getElementById('authentication').innerHTML = 'failed (card)';
        }
     } else {
        document.getElementById('authentication').innerHTML = 'failed (frontend)';
     }
   }
   http.onloadend = function () {};
   spinner('authentication');
   http.send(JSON.stringify(authtest));
}

function sendAuth() {
   var http = new XMLHttpRequest();
   http.open('POST', '/authenticate', true);
   http.setRequestHeader('Content-Type', 'application/json; charset=UTF-8');
   http.onreadystatechange = function() {
     if (this.readyState == 4 && this.status == 200) {
        let signerInfo = JSON.parse(this.responseText);
        document.getElementById('authentication').innerHTML = renderObject('Käyttäjä tunnistettu',  signerInfo);
        console.log(signerInfo);
     } else {
        document.getElementById('authentication').innerHTML = 'failed (backend)';
     }
   }
   http.onloadend = function () {};
   http.send(JSON.stringify(authresponse));
}

"))

(def style
"
.spinner {
  width: 14px;
  height: 14px;
  border: solid black 1px;
  animation-name: spin;
  animation-duration: 2000ms;
  animation-iteration-count: infinite;
  animation-timing-function: linear;
}
@keyframes spin {
  from {transform:rotate(0deg);}
  to {transform:rotate(360deg);}
}
")

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



(defn router [req]
   ; (println "router: " req)
   (cond

      (= "/sign" (:uri req))
         (let [data (json/read-str (:body req) :key-fn keyword)]
            (if-let
               [errs
                  (crypt/validation-errors
                     (:signature data)
                     (byte-array (codec/base64-decode-octets test-pdf-pkcs))
                     (:chain data))]
               (do
                  (println "Signature failure: " errs)
                  {:status 400
                   :headers {"Content-Type" "text/plain"}
                   :body (str "Invalid signature: " errs)})
               (let [pdf-data (pdf/read-file "pdf/testi.pdf-signable")
                     pkcs7 (pdf/make-pkcs7 data pdf-data)]
                  (pdf/write-file! "pdf/test-allekirjoitettu.pdf"
                     (pdf/write-signature! pdf-data pkcs7))
                  {:status 200
                   :headers {"Content-Type" "text/plain"}
                   :body "OK"})))

      (= "/verify" (:uri req))
         (let [pdf-data (pdf/read-file "pdf/test-allekirjoitettu.pdf")
               sigp (pdf/cursory-verify-signature pdf-data)]
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

      (= "/load-cas" (:uri req))
         (do
            (crypt/add-trust-roots! "trust-roots.pem")
            {:status 200
             :headers {"Content-Type" "text/html"}
             :body
                (str "<ul>"
                   (reduce
                      (fn [tail cert]
                         (str "<li>" (crypt/cert-name cert) tail))
                      "</ul>"
                      @crypt/a-signature-trust-roots))})

      (= "/authenticate" (:uri req))
         (let [data (json/read-str (:body req) :key-fn keyword)]
            (if-let [signer (and data (crypt/signer-info (:signature data) full-authentication-challenge (:chain data)))]
               {:status 200
                :headers {"Content-Type" "text/plain"}
                :body (json/write-str signer)}
               {:status 300
                :headers {"Content-Type" "text/plain"}
                :body "No"}))

      :else
         {:status 200
          :body
             (html
                [:html
                   [:head
                      [:title "Toimikorttitesti"]
                      [:script js-code]
                      [:style  style]
                      [:meta {:charset "UTF-8"}]]
                   [:body

                      [:p "Digisign version haku: "
                         [:button {:onClick "getVersion()"}
                         "hae"]]
                      [:p {:id "mpollux"} ""]

                      [:p "Allekirjoituksen teko kortilla: "
                         [:button {:onClick "getSignature()"}
                         "allekirjoita"]]
                      [:p {:id "signature"} ""]

                      [:p "Allekirjoituksen tallennus pdf:ään: "
                         [:button {:onClick "sendSignature()"}
                         "lähetä"]]
                      [:p {:id "sent"} ""]

                      [:p "Allekirjoituksen varmistus pdf:stä: "
                         [:button {:onClick "verifySignature()"}
                         "tarkista"]]
                      [:p {:id "status"} ""]

                      [:p "Tunnistautuminen: "
                         [:button {:onClick "authenticate()"}
                         "tunnistaudu"]]
                      [:p {:id "authentication"} ""]

                      [:p "Varmenteet: "
                         [:button {:onClick "loadCAs()"}
                         "lataa"]]
                      [:p {:id "cas"} ""]


                      ]])}))

(defn wrap-content-type [response content-type]
   (if (get-in response [:headers "Content-Type"])
      response
      (assoc-in response [:headers "Content-Type"] content-type)))

(defn wrap-body-string [handler]
  (fn [request]
      (let [body-str (ring.util.request/body-string request)]
         (handler (assoc request :body body-str)))))

(def app
   (->
      router
      (mparams/wrap-multipart-params)
      (params/wrap-params)
      (wrap-body-string)
      ))

(def default-opts
   {:port 3000
    :join false
    :host "localhost"})

(defn start [opts]
   (jetty/run-jetty app
      (select-keys opts [:port :join :host])))

(defn go []
   (start default-opts))

(defn handle-args [opts args]
   (cond
      (empty? args)
         (start opts)
      (contains? #{"-h" "--help"} (first args))
         (do
            (println "Usage: java -jar puumerkki.jar [-h] [-t|--trust-roots <pemfile>]")
            0)
      (and (contains? #{"-t" "--trust-roost"} (first args)) (not (empty? (rest args))))
         (do
            (crypt/add-trust-roots! (second args))
            (handle-args opts (rest (rest args))))
      :else
         (do
            (println "Invalid arguments: " args ". Use -h for help.")
            nil)))

(defn -main [& args]
   (try
      (handle-args default-opts args)
      (catch Exception e
         (println "ERROR: " e)
         1)))

