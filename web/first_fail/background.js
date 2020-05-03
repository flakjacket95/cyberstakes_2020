console.log("In background");

let tabMap = {};

var rpc = chrome.runtime.connectNative('com.security.password_manager');
rpc.onMessage.addListener(function(msg) {
    console.log("Got rpc message",msg)
    if (msg.tabid === undefined) {
      return;
    }
    let tab = tabMap[msg.tabid];
    if (tab === undefined)
      return;
    tab.onRPCMessage(msg);
});
rpc.onDisconnect.addListener(function() {
    console.log("RPC Disconnected!");
});

class PasswordManager {
  constructor(tabid, port) {
    this.tabid = tabid;
    this.port = port;

    this.onTabMessage = this.onTabMessage.bind(this)
  }
  onTabMessage(msg) {
    if (msg.type === 'open_manager') {
      chrome.tabs.create({ url: chrome.runtime.getURL("manager.html") });
    }
    let packet = { tabid:this.tabid, msg:msg};
    console.log('Sending %O',packet)
    rpc.postMessage(packet);
  }
  onRPCMessage(msg) {
    this.port.postMessage(msg.msg);
  }
}

chrome.runtime.onConnect.addListener(port => {
    console.log("Connect %O",port);
    let tab = port.sender.tab;
    console.log("tab id:",tab.id);
    let manager = new PasswordManager(tab.id, port);
    tabMap[tab.id] = manager;
    port.onMessage.addListener(manager.onTabMessage);
});


