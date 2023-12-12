function isMaliciousDomain(domain) {
  // Check for hyphens and symbols in the domain
  if (/[^\w.-]/.test(domain)) {
    return true;
  }

  // Check if the domain is entirely numeric
  if (/^\d+$/.test(domain)) {
    return true;
  }

  // Add more rules as needed

  return false;
}

function homographCheck(originalDomain, punycodeDomain) {
  return originalDomain !== punycodeDomain;
}

function getProtocolAndDomain(url) {
  try {
    var urlObject = new URL(url);
    var protocol = urlObject.protocol.replace(':', '');
    var domain = urlObject.hostname;
    return { protocol, domain };
  } catch (error) {
    console.error('Error parsing URL:', error);
    return { protocol: '', domain: '' };
  }
}

function checkCertificateValidity(domain) {
  const url = `https://check-ssl.p.rapidapi.com/sslcheck?domain=${domain}`;
  const options = {
    method: 'GET',
    headers: {
      'X-RapidAPI-Key': 'your-api-key',
      'X-RapidAPI-Host': 'check-ssl.p.rapidapi.com'
    }
  };

  return fetch(url, options)
    .then(response => response.json())
    .then(result => {
      console.log(result);

      if (result.isvalidCertificate) {
        document.getElementById("comment").textContent = 'Certificate is valid';
      } else {
        document.getElementById("comment").textContent = 'Certificate might not be valid';
      }

      // Check for malicious domain based on additional criteria
      if (isMaliciousDomain(domain)) {
        document.getElementById("comment").textContent = 'Malicious domain detected';
      }

      // Check for homograph attack
      const punycodeDomain = punycode.toASCII(domain);
      if (homographCheck(domain, punycodeDomain)) {
        document.getElementById("comment").textContent = 'Possible homograph attack';
      }
    })
    .catch(error => {
      console.error(error);
    });
}

function getURL() {
  browser.tabs.query({ active: true, currentWindow: true }, function(tabs) {
    var url = tabs[0].url;
    var { protocol, domain } = getProtocolAndDomain(url);
    document.getElementById("url").textContent = "Domain: " + domain;

    // Check if the URL uses HTTPS
    if (protocol === 'https') {
      // Check the SSL certificate validity
      checkCertificateValidity(domain);
    } else {
      var comment = 'Site might not be safe (uses HTTP)';
      document.getElementById("comment").textContent = comment;
    }

    document.getElementById("url").style.color = "#2f3330";
  });
}

document.getElementById("checkBTN").addEventListener("click", getURL);
