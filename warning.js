// warning.js
function proceedToOriginalPage() {
    // window.location.href = originalUrl;
    console.log('Proceeding to original page');

    // Retrieve the original URL from local storage
    const originalUrl = localStorage.getItem('originalUrl');
    console.log('Retrieved original URL:', originalUrl);

     // Mark that the user has been redirected to the warning page for this URL
    sessionStorage.setItem(`seenWarning_${originalUrl}`, true);

    setTimeout(() => {
    window.location.href = originalUrl;
      }, 2000);
}

function proceedToSafety() {
    // window.location.href = originalUrl;
    console.log('Proceeding to safety page');

    // Retrieve the original URL from local storage
    const originalUrl = localStorage.getItem('originalUrl');
    console.log('Retrieved original URL:', originalUrl);

     // Mark that the user has been redirected to the warning page for this URL
    sessionStorage.setItem(`seenWarning_${originalUrl}`, false);

    setTimeout(() => {
    window.location.href = 'https://www.google.com/';
      }, 1500);
}

document.getElementById('proceedButton').addEventListener('click', proceedToOriginalPage);

document.getElementById('safetyButton').addEventListener('click', proceedToSafety);

/* chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {
    
    if (message.action === 'simulateProceedToOriginalPage') {
        console.log('Message received in warning.js:', message);
        window.location.href = 'https://www.google.com/';
    }
});
 */