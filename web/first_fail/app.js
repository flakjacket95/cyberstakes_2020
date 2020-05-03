// Privileged page inject

// Inject API into the page
var s = document.createElement('script');
s.src = chrome.extension.getURL('api.js');
s.onload = function() {
      this.parentNode.removeChild(this);
};
(document.head||document.documentElement).appendChild(s);

// Open port to backend
var port = chrome.runtime.connect('cegaaaajnnledpnkmnjenhbakdijgcjo',{name: "api"});

let web = null;

port.onMessage.addListener(msg => {
  console.log("Content script got from rpc:",msg);
  if (msg.type === 'get_password_response' || msg.type === 'pong') {
    web.postMessage(msg);
  }
})

window.addEventListener("message", function(event) {
  // We only accept messages from ourselves
  if (event.source != window)
    return;

  web = event.source;

  let msg = event.data;
  console.log("Content script got from web:",msg);

  if (msg.type === 'add_password') {
    msg.host = location.host;
  } else if (msg.type === 'get_password' || msg.type === 'entries') {
    // Make domain wildcard pattern to match any subdomain
    let domain = location.host.split('.').slice(-2).join('.')
    msg.pattern = `*${domain}`;
  }
  
  port.postMessage(msg);
});
