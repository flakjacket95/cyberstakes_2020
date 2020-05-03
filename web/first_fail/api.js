// Unprivileged page inject


let resolves = {};

(function (exports) {
  exports.ping = function() {
    return new Promise((resolve, reject) => {
      resolves['pong'] = resolve;
      window.postMessage({ 
        type:'ping',
      }, "*");
    });
  }
  exports.addPassword = function(username, password) {
    window.postMessage({ 
      type:'add_password',
      username: username,
      password: password
    }, "*");
  };
  exports.openManager = function() {
    window.postMessage({ 
      type:'open_manager',
    }, "*");
  };
  exports.getPassword = function() {
    return new Promise((resolve, reject) => {
      resolves['get_password_response'] = (msg)=>{
        console.log(msg);
        resolve(msg.account);

      }
      window.postMessage({ 
        type:'get_password',
      }, "*");
    });
  };
})(window.PasswordManager = {});

window.addEventListener("message", function(event) {
  // We only accept messages from ourselves
  if (event.source != window)
    return;

  let msg = event.data;
  if (msg.type in resolves) {
    resolves[msg.type](msg);
  }
});


// Auto fill passwords in the page
for (let form of document.forms) {
  let passwords = [];
  let other = [];
  for (let inp of form.querySelectorAll('form input')) {
    if (inp.type === 'password')
      passwords.push(inp);
    else if (inp.type === "text" || inp.type === "")
      other.push(inp);
  }

  if (passwords.length > 0) {
    // Get current password
    PasswordManager.getPassword().then(account=>{
      if (account === null)
        return;
      for (let pw of passwords)
        pw.value = account.password;
      for (let inp of other)
        inp.value = account.username;
    });

    let submit_real = form.onsubmit;
    form.onsubmit = function(evt) {
      let username = '';
      let pass = passwords[0].value;
      if (other.length > 0)
        username = other[0].value;
      PasswordManager.addPassword(username, pass);
      return submit_real.call(this,evt);
    }
  }
}
