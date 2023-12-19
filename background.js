// background.js

// Load punycode.min.js from CDN
const script = document.createElement('script');
script.src = 'https://cdnjs.cloudflare.com/ajax/libs/punycode/2.1.0/punycode.min.js';
script.onload = handleScriptLoad; // Call your function once the script is loaded
document.head.appendChild(script);

function handleScriptLoad() {
  let previousDomain = '';

  // Function to handle web navigation events
  // Function to handle web navigation events
async function handleNavigation(details) {
  if (details.frameId === 0 && details.url) {
    const { protocol, domain } = getProtocolAndDomain(details.url);

    // Check if the domain has changed
    if (domain !== previousDomain) {
      previousDomain = domain; // Update the previous domain

      // Check conditions
      const isMalicious = await checkIsMalicious(domain);
      const punycodeDomain = punycode.toASCII(domain);
      const hasHomograph = checkHomograph(domain, punycodeDomain);
      const isValidTLD = checkTopLevelDomain(domain);
      const isGoogleSafe = await checkGoogleSafe(details.url);
      const isHTTPS = protocol === 'https';
      console.log(!isHTTPS);
      console.log(isMalicious);
      console.log(hasHomograph);
      console.log(!isValidTLD);
      // Trigger the popup when at least one condition is met
      if (!isHTTPS || isMalicious || hasHomograph || !isValidTLD || isGoogleSafe) {
        showPopup();
      }
      else {
        browser.browserAction.setBadgeText({ text: "" });
      }
    }
  }
}

  // Add a listener for web navigation events
  browser.webNavigation.onBeforeNavigate.addListener(handleNavigation);

  // Function to get the protocol and domain from a URL
  function getProtocolAndDomain(url) {
    try {
      const urlObject = new URL(url);
      const protocol = urlObject.protocol.replace(':', '');
      const domain = urlObject.hostname;
      return { protocol, domain };
    } catch (error) {
      console.error('Error parsing URL:', error);
      return { protocol: '', domain: '' };
    }
  }

  // Placeholder functions, replace with your actual logic
  async function checkIsMalicious(domain) {
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

  function checkHomograph(originalDomain, punycodeDomain) {
    return originalDomain !== punycodeDomain;
  }

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
    return acceptedTLDs.includes(tld);
  }

  async function checkGoogleSafe(url) {
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
                return true;
            } else {
                return false;
            }
        })
        .catch(error => {
            console.error(error);
            return true;
        });
}

  // Function to show the extension popup
  function showPopup() {
    browser.browserAction.setBadgeText({ text: "!" });
    const notificationOptions = {
      type: 'basic',
      iconUrl: 'path/to/icon.png',
      title: 'Proceed With Caution',
      message: 'This website might be malicious, open the extension to view problems',
    };
  
    // Create and show the notification
    browser.notifications.create(notificationOptions);
    console.log("Popup triggered");
  }
}
