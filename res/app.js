var mpolluxInfo  = false;
var mpolluxUrl   = 'https://localhost:53952';
var signature    = false;
var authresponse = false;
var user         = false;
var currentTab   = false;

function navigateLink(where) {
   event.preventDefault();
   console.log(" -> " + where);
   let elem = document.getElementById(where);
   if (elem) {
      if (currentTab) {
         currentTab.style.display = 'none';
      }
      elem.style.display = 'inline-block';
      currentTab = elem;
   }
   return false;
}

function toSmallString(val) {
   let s = val + '';
   if (s.length > 100) {
      s = '<font size=-4>' + val + '</font>';
   }
   return s;
}

function showMe(e, text) {
   e.innerHTML = text;
   e.style.display = 'inline-block';
}

function clearMe(e) {
   e.innerHTML = '';
   e.style.display = 'none';
}

function showId(id, text) {
   let elem = document.getElementById(id);
   if (elem) {
      showMe(elem, text);
   } else {
      console.log('cannot find object with id ' + id);
   }
}

function showIdSpin(id, text) {
   showId(id, text + ' <div class=spinner></div>');
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


// reloads each time without caching, so that we'll see whether digisign is
// alive at frontend before attempting to use it
function getVersion(target, cont) {
   let http = new XMLHttpRequest();
   http.open('GET', mpolluxUrl + '/version');
   http.setRequestHeader('Content-Type', 'application/json; charset=UTF-8');
   http.overrideMimeType('application/json'); // avoid xml parsing error due to missing mime type

   http.onreadystatechange = function() {
     if (this.readyState != 4) return;
     if (this.status == 200) {
        mpolluxInfo = JSON.parse(this.responseText);
        if (cont) {
           cont(target, mpolluxInfo);
        } else {
           showId(target, renderObject('versiotiedot', mpolluxInfo));
        }
     } else {
        showId(target, 'Digisign ei käytettävissä');
     }
   }
   http.timeout = 2000;
   showId(target, 'yhdistetään digisigniin');
   http.send();
}

function loadCAs() {
   var http = new XMLHttpRequest();
   http.open('GET', 'load-cas');
   http.onreadystatechange = function() {
     if (this.readyState != 4) return;
     if (this.status == 200) {
        showId('cas', this.responseText);
     } else {
        showId('cas', 'error');
     }
   }
   showIdSpin('cas');
   http.send();
}

// pipelines
//  - makeSignature -> sendSignature -> verifySignature

function makeSignature(target, request) {
   var http = new XMLHttpRequest();
   http.open('POST', mpolluxUrl + '/sign', true);
   http.setRequestHeader('Content-Type', 'application/json; charset=UTF-8');
   http.overrideMimeType('application/json');
   http.onreadystatechange = function() {
     if (this.readyState != 4) return;
     if (this.status == 200) {
        signature = JSON.parse(this.responseText);
        signature.request = request; // for verification
        sendSignature(target, signature); // + request w/ hmac later to avoid backend state
     } else {
        showId(target, 'failed');
     }
   }
   showIdSpin(target, 'allekirjoitetaan kortilla');
   http.send(JSON.stringify(request));
}

// send signature and request leading to it to backend for saving to pdf
function sendSignature(target, signature) {
   var http = new XMLHttpRequest();
   http.open('POST', 'sign', true);
   http.setRequestHeader('Content-Type', 'application/json; charset=UTF-8');
   http.onreadystatechange = function() {
     if (this.readyState != 4) return;
     if (this.status == 200) {
        verifySignature(target);
     } else {
        showId(target, 'failed');
     }
   }
   showIdSpin(target, 'lähetetään');
   http.send(JSON.stringify(signature));
}

function verifySignature(target) {
   var http = new XMLHttpRequest();
   http.open('GET', 'verify', true);
   http.onreadystatechange = function() {
     if (this.readyState != 4) return;
     if (this.status == 200) {
        showId(target, 'OK'); // this.response
     } else {
        showId(target, 'allekirjoitusta ei hyväksytä');
     }
   }
   showIdSpin(target, 'varmistetaan allekirjoitus');
   http.send(JSON.stringify(signature));
}

function sendAuth(target, response, challenge) {
   var http = new XMLHttpRequest();
   http.open('POST', 'authenticate', true);
   http.setRequestHeader('Content-Type', 'application/json; charset=UTF-8');
   http.onreadystatechange = function() {
     if (this.readyState != 4) return;
     if (this.status == 200) {
        let signerInfo = JSON.parse(this.responseText);
        showId(target, renderObject('Käyttäjä tunnistettu',  signerInfo));
        updateLogin(signerInfo);
     } else {
        showId(target, 'failed (backend)');
     }
   }
   response['signedData'] = challenge; // return to backend for verification
   showId(target, 'lähetetään tiedot');
   http.send(JSON.stringify(response));
}

function authenticate(target, challenge) {
   var http = new XMLHttpRequest();
   http.open('POST', mpolluxUrl + '/sign', true);
   http.setRequestHeader('Content-Type', 'application/json; charset=UTF-8');
   http.onreadystatechange = function() {
     if (this.readyState != 4) return;
     if (this.status == 200) {
        authresponse = JSON.parse(this.responseText);
        if (authresponse.status == 'ok') {
           sendAuth(target, authresponse, challenge);
        } else {
           showId(target, 'failed (card)');
        }
     } else {
        showId(target, 'failed (digisign)');
     }
   }
   showId(target, 'toimikortti');
   http.send(JSON.stringify(challenge));
}

function getAuthChallenge(target, version) {
   let args = {};
   let http = new XMLHttpRequest();
   http.open('POST', 'auth-challenge', true);
   http.onreadystatechange = function() {
     if (this.readyState != 4) return;
     if (this.status == 200) {
        authenticate(target, JSON.parse(this.responseText));
     } else {
        showId(target, 'failed (backend challenge)');
     }
   }
   showId(target, 'starting authentication');
   args.host = window.location.hostname;
   args.version = version;
   args.url = mpolluxUrl;
   args.type = 'digisign'; // for future extension
   http.send(JSON.stringify(args));
}

function startAuthentication() {
   if (location.protocol !== "https:") {
      alert('must authenticate over https');
      return;
   }
   getVersion('authentication', getAuthChallenge);
}

function getPdfSignRequest(target, version) {
   let args = {};
   let http = new XMLHttpRequest();
   http.open('POST', 'pre-sign', true);
   http.onreadystatechange = function() {
     if (this.readyState != 4) return;
     if (this.status == 200) {
        makeSignature(target, JSON.parse(this.responseText));
     } else {
        showId(target, 'pre-sign');
     }
   }
   args.host = window.location.hostname;
   args.version = version;
   args.url = mpolluxUrl;
   args.type = 'digisign'; // for future extension
   showIdSpin(target, 'haetaan tiedot allekirjoitusta varten');
   http.send(JSON.stringify(args));
}

function startSigning(target) {
   if (location.protocol !== "https:") {
      alert('can only sign via https');
      return;
   }
   showIdSpin(target, 'aloitetaan');
   getVersion(target, getPdfSignRequest);
}

function updateLogin(info) {
   user = info;
   if(info) {
      showId('loginbox', info.name + " <a href='logout'>logout</a>");
   } else {
      showId('loginbox',
         "<a onclick='navigateLink(\"tunnistautuminen\")' href='tunnistautuminen'>&#x1F464;</a>");
   }
}

function getSession() {
   let http = new XMLHttpRequest();
   http.open('GET', 'session', true);
   http.onreadystatechange = function() {
     if (this.readyState != 4) return;
     if (this.status == 200) {
        updateLogin(JSON.parse(this.responseText));
     }
   }
   http.send();
}

function main() {
   getSession(); // update login info if already logged in via cookie
   navigateLink("etusivu");
}











