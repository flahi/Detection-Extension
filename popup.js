var dom;

// Function to check if the domain is malicious
function isMaliciousDomain(domain) {
  // Check for hyphens and symbols in the domain
  if (/[^\w.-]/.test(domain)) {
    return '<span class="malicious">might be malicious,</span>';
  }

  // Check if the domain is entirely numeric
  if (/^\d+$/.test(domain)) {
    return '<span class="malicious">might be malicious,</span>';
  }

  // Add more rules as needed

  return '<span class="good">no malicious url signature</span>';
}

// Function to check for homograph attacks
function homographCheck(originalDomain, punycodeDomain) {
  return originalDomain !== punycodeDomain ? '<span class="homograph">homographic deception</span>' : '<span class="good">no homographic deception</span>';
}

// Function to check the top-level domain
function checkTopLevelDomain(domain) {
  const acceptedTLDs = [".com", ".net", ".org", ".gov", ".edu", ".mil", ".int", ".eu", ".biz", ".info",
  ".museum", ".coop", ".aero", ".travel", ".cat", ".jobs", ".tel", ".pro", ".asia",
  ".post", ".xxx", ".ac", ".gov", ".edu", ".co", ".io", ".ai", ".ly", ".tv", ".me",
  ".us", ".uk", ".ca", ".au", ".nz", ".za", ".ae", ".sa", ".qa", ".kw", ".bh", ".om",
  ".eg", ".br", ".mx", ".ar", ".es", ".fr", ".de", ".it", ".nl", ".se", ".no", ".dk",
  ".fi", ".ch", ".at", ".be", ".lu", ".ie", ".sg", ".my", ".ph", ".th", ".vn", ".id",
  ".in", ".pk", ".bd", ".lk", ".np", ".jp", ".kr", ".cn", ".hk", ".tw", ".mo", ".ru",
  ".ua", ".pl", ".cz", ".hu", ".ro", ".bg", ".gr", ".tr", ".il", ".jo", ".lb", ".qa",
  ".kw", ".bh", ".om", ".sa", ".ae", ".ng", ".ke", ".za", ".tz", ".ug"
];
  const tld = `.${domain.split('.').pop()}`.toLowerCase();
  if (!acceptedTLDs.includes(tld)) {
    return '<span class="invalid-tld">invalid or suspicious TLD</span>';
  } else {
    return '<span class="good">trusted TLD</span>';
  }
}

// Function to get the protocol and domain from a URL
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

// Function to check the SSL certificate validity
function checkCertificateValidity() {
  const sslUrl = `https://check-ssl.p.rapidapi.com/sslcheck?domain=${dom}`;
  const options = {
    method: 'GET',
    headers: {
      'X-RapidAPI-Key': 'a17b0e6e48msh3daae5ea2045e44p1611d1jsn3184f71cf709',
      'X-RapidAPI-Host': 'check-ssl.p.rapidapi.com'
    }
  };

  return fetch(sslUrl, options)
    .then(response => response.json())
    .then(result => {
      console.log(result);

      if (result.isvalidCertificate) {
        return '<span class="good">Certificate is valid</span>';
      } else {
        return '<span class="invalid-certificate">Certificate might not be valid</span>';
      }
    })
    .catch(error => {
      console.error(error);
      return '<span class="error">Error checking certificate</span>';
    });
}

// Function using Google's safe browsing API
function isGoogleSafe(url) {
  const apiSafeBrowseKey = 'AIzaSyCLqzT5iLZImfh4LU6yS8l3GMvLnCY_or8';
  const safeBrowseUrl = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiSafeBrowseKey}`;
  const safeBrowsingOptions = {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      client: {
        clientId: 'detection-extension',
        clientVersion: '1.5.2',
      },
      threatInfo: {
        threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
        platformTypes: ['ANY_PLATFORM'],
        threatEntryTypes: ['URL'],
        threatEntries: [{ 'url': url }],
      },
    }),
  };
  
  return fetch(safeBrowseUrl, safeBrowsingOptions)
    .then(response => response.json())
    .then(result => {
      console.log(result);

      if (result.matches && result.matches.length > 0) {
        return '<span class="malicious">flagged by Google Safe Browsing</span>';
      } else {
        return '<span class="good">Google Safe Browsing approved</span>';
      }
    })
    .catch(error => {
      console.error(error);
      return '<span class="error">Error checking certificate</span>';
    });
}

// Function to get the URL and perform checks
async function getURL(url) {
  try {
    const tabs = await browser.tabs.query({ active: true, currentWindow: true });
    const url = tabs[0].url;
    const { protocol, domain } = getProtocolAndDomain(url);
    dom = domain;
    document.getElementById("url").innerHTML = "Domain: " + domain;
    
    let comments = [];
    comments.push('Analysis');
    if (protocol === 'https') {
      comments.push(isMaliciousDomain(domain));
      const punycodeDomain = punycode.toASCII(domain);
      comments.push(homographCheck(domain, punycodeDomain));
      comments.push(checkTopLevelDomain(domain));

      try {
        const safeBrowsingComment = await isGoogleSafe(url);
        comments.push(safeBrowsingComment);
      } catch (err) {
        comments.push('<span class="error">Error checking Google Safe Browsing</span>');
        console.error(err);
      }

      comments.push('<span class="good">secure connection</span>');
    } else {
      comments.push('<span class="warning">insecure connection (HTTP)</span>');
    }

    document.getElementById("comment").innerHTML = comments.join('<br>');
    document.getElementById("url").style.color = "#2f3330";
  } catch (error) {
    console.error('Error in getURL:', error);
  }
}

// Event listener for the button click
document.getElementById('checkBTN').addEventListener('click', function () {
  checkCertificateValidity().then(comment => {
    document.getElementById('comment').innerHTML = comment.replace(/\n/g, '<br>');
  });
});
getURL();
