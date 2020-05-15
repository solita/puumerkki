(ns puumerkki.main
  (:require
     [puumerkki.codec :as codec]
     [puumerkki.pdf :as pdf]

     [ring.adapter.jetty :as jetty]
     [ring.middleware.params :as params]            ;; query string & body params
     [ring.middleware.multipart-params :as mparams] ;; post body
     [hiccup.core :refer [html]]
     [clojure.data.json :as json])

  (:import [org.apache.pdfbox.pdmodel.interactive.digitalsignature PDSignature SignatureInterface]
           [org.apache.pdfbox.pdmodel PDDocument]
           ;[org.apache.pdfbox.pdmodel.graphics.xobject PDPixelMap PDXObject PDJpeg]
           [org.apache.pdfbox.io RandomAccessFile]
           [org.apache.commons.io IOUtils]
           (org.apache.pdfbox.cos COSName)
           (java.security MessageDigest)
           [java.util Calendar]
           [java.io File FileInputStream FileOutputStream ByteArrayOutputStream]
           (org.apache.commons.codec.digest DigestUtils)))

(def origin "https://localhost")


;(pdf/add-signature-space "pdf/testi.pdf" "pdf/testi.pdf-signable" "Päivi Päättäjä")  ;; make pdf/testi.pdf-signable
(pdf/add-watermarked-signature-space "pdf/testi.pdf" "pdf/testi.pdf-signable" "Stephen Signer" "pdf/stamp.jpeg" 100 300)

(def test-pdf-data (pdf/read-file "pdf/testi.pdf-signable"))          ;;
(def test-pdf-pkcs (pdf/compute-base64-pkcs test-pdf-data))       ;; to be sent to mpollux from https frontend

(def authentication-challenge
   (codec/base64-encode
      (str origin "secretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecretsecret")))



(def js-code
(str "var pkcs = '" test-pdf-pkcs "';
var auth = '" authentication-challenge "';

var mpolluxInfo  = false;
var mpolluxUrl   = 'https://localhost:53952';
var signature    = false;
var authresponse = false;

function renderObject(name,exp) {
   info = name + ':<ul>';
   Object.keys(exp).forEach(function(key) {
      var val = '' + exp[key];
      if (val.length > 100) {
         val = '<font size=-4>' + val + '</font>';
      }
      info += '<li>' + key + ': ' + val;
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
   var http = new XMLHttpRequest();
   http.open('POST', mpolluxUrl + '/sign', true);
   http.setRequestHeader('Content-Type', 'application/json; charset=UTF-8');
   http.onreadystatechange = function() {
     if (this.readyState == 4 && this.status == 200) {
        authresponse = JSON.parse(this.responseText);
        // document.getElementById('authentication').innerHTML = renderObject('tunnistautuminen', authresponse);
        sendAuth();
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
        document.getElementById('authentication').innerHTML = this.response;
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
         (let [data (json/read-str (:body req) :key-fn keyword)
               pdf-data (pdf/read-file "pdf/testi.pdf-signable")
               pkcs7 (pdf/make-pkcs7 data pdf-data)
             ]
            (pdf/write-file! "pdf/test-allekirjoitettu.pdf"
               (pdf/write-signature! pdf-data pkcs7))
            {:status 200
             :headers {"Content-Type" "text/plain"}
             :body "OK"})

      (= "/verify" (:uri req))
         (let [pdf-data (pdf/read-file "pdf/test-allekirjoitettu.pdf")
               sigp (pdf/cursory-verify-signature pdf-data)]
            (if sigp
               {:status 200
                :headers {"Content-Type" "text/plain"}
                :body
                   (str "OK: <pre>"
                      (with-out-str
                         (clojure.pprint/pprint sigp))
                      "</pre>")
               }
               {:status 300
                :headers {"Content-Type" "text/plain"}
                :body "Virhe."}))

      (= "/authenticate" (:uri req))
         (let [data (json/read-str (:body req) :key-fn keyword)
               cert (codec/asn1-decode (codec/base64-decode-octets (first (get data :chain))))
               fst (cert-givenname cert)
               snd (cert-surname cert)]
            (if (and data fst snd)
               {:status 200
                :headers {"Content-Type" "text/plain"}
                :body
                   (str "Card owner: " fst " " snd)}
               {:status 300
                :headers {"Content-Type" "text/plain"}
                :body "Virhe."}))

      :else
         {:status 200
          :body
             (html
                [:html
                   [:head
                      [:title "allekirjoitustesti"]
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
                         "tarkasta"]]
                      [:p {:id "status"} ""]

                      [:p "Tunnistautuminen: "
                         [:button {:onClick "authenticate()"}
                         "tunnistaudu"]]
                      [:p {:id "authentication"} ""]

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

(defn go []
   (jetty/run-jetty app {:port 3000 :join false}))

(defn -main [& args]
   (jetty/run-jetty app {:port 3000 :join false}))

