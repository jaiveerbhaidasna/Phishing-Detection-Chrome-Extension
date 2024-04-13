// background.js
chrome.runtime.onInstalled.addListener(function () {
    console.log('Phishing Detector extension installed.');
});

chrome.webNavigation.onCompleted.addListener(function (details) {
    // Check if this is the main frame of the tab
    if (details.frameId === 0) {
        console.log('Navigation completed:', details);

        // Use sender.tab.url to get the current tab's URL directly
        const desiredURL = details.url;
        console.log('Current URL:', desiredURL);

        const hasSeenWarning = sessionStorage.getItem(`seenWarning_${desiredURL}`);
        console.log('warning seen:', hasSeenWarning)

    if (!hasSeenWarning) {
      fetch('http://localhost:5000/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ url: desiredURL }),
      })
        .then(response => response.json())
        .then(result => {
          console.log('Phishing Likelihood:', result.phishing_likelihood);

          if (result.phishing_likelihood > 0.5) {
            console.log('Phishing Detected! Take action.');

            // Store the original URL in local storage
            localStorage.setItem('originalUrl', desiredURL);

            // Mark that the user has been redirected to the warning page for this URL
            sessionStorage.setItem(`seenWarning_${desiredURL}`, true);

            chrome.tabs.update({ url: 'warning.html' }, function(updatedTab) {
              console.log('Sending message to warning.js');
              chrome.tabs.sendMessage(updatedTab.id, { action: 'provideOriginalUrl' });
            });
          }
        })
        .catch(error => {
          console.error('Error:', error);
        });
    }
  }
});

// Listen for messages from the warning.js script
/* chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {
    if (message.action === 'proceedButtonPushed') {
        console.log('PROCEED BUTTON PUSHED')
    
        // Get the active tab
        chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
          const activeTab = tabs[0];
    
      }); 
    }
  }); */
