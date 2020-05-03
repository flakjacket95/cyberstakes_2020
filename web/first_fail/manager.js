// JavaScript for the manager.html view

var port = chrome.runtime.connect('cegaaaajnnledpnkmnjenhbakdijgcjo',{name: "api"});

port.onMessage.addListener(msg => {
  console.log(msg)
  if (msg.type === 'sites_response') {
    // Retrive passwords for all sites
    for (let site of msg.sites) {
      console.log(site)
      port.postMessage({
        type: 'entries',
        pattern: site
      });
    }
  }

  if (msg.type === 'entries_response') {
    let site = `
<div>
  <h3>${msg.pattern}</h3>`;
    for (let account of msg.entries) {
      eval(account);
      site += `
      <div class="account">
      <b>Username:</b> ${username}<br/>
      <b>Password:</b> ${password}
      </div>`
    }
    site += `
  </div>`;
    let div = document.createElement('div');
    div.innerHTML = site;
    document.getElementById('sites').append(div);
  }
})

port.postMessage({
  type: 'sites',
});
