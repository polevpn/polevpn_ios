//
//  ViewController.swift
//  wkwebview
//

import UIKit
import WebKit
import Polevpnmobile
import SwiftyJSON
import NetworkExtension


class ViewController: UIViewController, WKNavigationDelegate, WKScriptMessageHandler {
    
    var webView: WKWebView!
    var polevpn: PolevpnmobilePoleVPN!
    var observerAdded: Bool = false
    var sharedData:UserDefaults!

    
    override func loadView() {
        webView = WKWebView()
        webView.navigationDelegate = self
        webView.configuration.userContentController.add(self, name: "ext")
        view = webView
        let paths = NSSearchPathForDirectoriesInDomains(.documentDirectory, .userDomainMask, true)
        let documentPath = paths[0]
                        
        var err:NSError?
        
        PolevpnmobileInitDB(documentPath+"/config.db",&err)
        PolevpnmobileSetLogPath(documentPath)
        
        sharedData = UserDefaults(suiteName: "group.com.polevpn.ios")
        
    }
    
    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
                
        let msg = JSON(parseJSON:message.body as! String)
        
        let seq = msg["seq"].intValue
        let name = msg["name"].stringValue
        let req = msg["req"].rawString()
        
        if name == "GetAllAccessServer" {
            let resp = PolevpnmobileGetAllAccessServer(req)
            respJson(seq: seq, msg: resp)
        } else if name == "AddAccessServer"{
            let resp = PolevpnmobileAddAccessServer(req)
            respJson(seq: seq, msg: resp)
        }else if name == "UpdateAccessServer" {
            let resp = PolevpnmobileUpdateAccessServer(req)
            respJson(seq: seq, msg: resp)
        } else if name == "DeleteAccessServer" {
            let resp = PolevpnmobileDeleteAccessServer(req)
            respJson(seq: seq, msg: resp)
        } else if name == "ConnectAccessServer" {
            
            var options:[String:NSObject] = [:]
            
            options["endpoint"] = msg["req"]["Endpoint"].stringValue as NSObject
            options["user"] = msg["req"]["User"].stringValue as NSObject
            options["pwd"] = msg["req"]["Password"].stringValue as NSObject
            options["sni"] = msg["req"]["Sni"].stringValue as NSObject
            options["skipSSLVerify"] = msg["req"]["SkipVerifySSL"].boolValue as NSObject
            options["useRemoteRouteRules"] = msg["req"]["UseRemoteRouteRules"].boolValue as NSObject
            options["localRouteRules"] = msg["req"]["LocalRouteRules"].stringValue as NSObject
            options["proxyDomains"] = msg["req"]["ProxyDomains"].stringValue as NSObject
            
            startVPN(options: options)
            
            respJson(seq: seq, msg: "{'Msg':'ok','Code':0}")
            
        } else if name == "StopAccessServer" {
            stopVPN()
            respJson(seq: seq, msg: "{'Msg':'ok','Code':0}")

        }else if name == "GetAllLogs" {
            
            
            var logs = sharedData.string(forKey: "logs")
            
            if logs  == nil {
                logs = ""
            }

            var msg = JSON()
            msg["event"] = "logs"
            msg["data"] = JSON()
            msg["data"]["logs"] = JSON(logs!)

                    
            DispatchQueue.main.async {
                self.webView.evaluateJavaScript("onCallback("+msg.rawString([:])!+")")
                return
            }
            
            respJson(seq: seq, msg: "{'Msg':'ok','Code':0}")

        }else if name == "GetUpDownBytes" {
            
            let upBytes = sharedData.integer(forKey: "upBytes")
            let downBytes = sharedData.integer(forKey: "downBytes")
                        
            var msg = JSON()
            msg["event"] = "bytes"
            msg["data"] = JSON()
            msg["data"]["UpBytes"] = JSON(upBytes)
            msg["data"]["DownBytes"] = JSON(downBytes)
                    
            DispatchQueue.main.async {
                self.webView.evaluateJavaScript("onCallback("+msg.rawString([:])!+")")
                return
            }
            
            respJson(seq: seq, msg: "{'Msg':'ok','Code':0}")

        }else if name == "GetVersion" {
            respJson(seq: seq, msg: "{'Msg':'ok','Code':0,'Version':'1.1.1'}")
        }
        else {
            respJson(seq: seq, msg: "{'Msg':'ok','Code':0}")
        }
    }
    
    func respJson(seq:Int,msg:String){
        webView.evaluateJavaScript("resolves["+String(seq)+"]("+msg+")")
        webView.evaluateJavaScript("resolves["+String(seq)+"] = undefined")
    }

    override func viewDidLoad() {
        super.viewDidLoad()
                
        let bundlePath = Bundle.main.bundlePath
        
        let path = "file://\(bundlePath)/static/index.html"
                                
        guard let url = URL(string: path) else {
            print("static file not found")
            return
        }
        
        let request = URLRequest(url: url)
        webView.load(request)
        webView.allowsBackForwardNavigationGestures = false
        
        DispatchQueue.main.asyncAfter(deadline: .now() + 1) {
            self.loadProviderManager { (manager) in
                guard manager != nil else{ return }
                
                if manager?.connection.status != .disconnected {
                    self.updateVPNStatus(manager!)
                    self.addVPNStatusObserver()
                }
            }
        }
    }
    
    func onAllocEvent(_ remoteIp:String?, ip: String?, dns: String?, routes: String?) {
        
        var msg = JSON()
        msg["event"] = "allocated"
        msg["data"] = JSON()
        msg["data"]["ip"] = JSON(ip!)
        msg["data"]["remoteIp"] = JSON(remoteIp!)
        msg["data"]["dns"] = JSON(dns!)
                
        DispatchQueue.main.async {
            
            self.webView.evaluateJavaScript("onCallback("+msg.rawString([:])!+")")
            return
        }

        print("onAllocEvent")
    }
    
    func onErrorEvent(_ errtype: String?, errmsg: String?) {
        
        var msg = JSON()
        msg["event"] = "error"
        msg["data"] = JSON()
        msg["data"]["error"] = JSON(errmsg!)
        
        DispatchQueue.main.async {
            self.webView.evaluateJavaScript("onCallback("+msg.rawString([:])!+")")
            return
        }

        print("onErrorEvent",errmsg!)

    }
    
    func onReconnectedEvent() {
        
        var msg = JSON()
        msg["event"] = "reconnected"
        
        DispatchQueue.main.async {
            self.webView.evaluateJavaScript("onCallback("+msg.rawString([:])!+")")
            return
        }
        
        print("onReconnectedEvent")

    }
    
    func onReconnectingEvent() {
        
        var msg = JSON()
        msg["event"] = "reconnecting"
        
        DispatchQueue.main.async {
            self.webView.evaluateJavaScript("onCallback("+msg.rawString([:])!+")")
            return
        }
        print("onReconnectingEvent")
    }
    
    func onStartedEvent() {
        var msg = JSON()
        msg["event"] = "started"
        
        DispatchQueue.main.async {
            self.webView.evaluateJavaScript("onCallback("+msg.rawString([:])!+")")
            return
        }
        print("onStartedEvent")
    }
    
    func onStoppedEvent() {
        
        var msg = JSON()
        msg["event"] = "stoped"
        
        DispatchQueue.main.async {
            self.webView.evaluateJavaScript("onCallback("+msg.rawString([:])!+")")
            return
        }
        print("onStoppedEvent")
    }
    
    private func makeManager() -> NETunnelProviderManager {
        let manager = NETunnelProviderManager()
        manager.localizedDescription = "PoleVPN"
        
        let proto = NETunnelProviderProtocol()
        
        proto.providerBundleIdentifier = "com.polevpn.ios.PacketTunnelProvider"
 
        proto.serverAddress = "PoleVPNServer"
        
        manager.protocolConfiguration = proto
        
        manager.isEnabled = true
        
        return manager
    }
    
    func updateVPNStatus(_ manager: NEVPNManager) {
                
        switch manager.connection.status {
        case .connected:
            self.onStartedEvent()
            
            let ip = self.sharedData.string(forKey: "ip")
            let dns = self.sharedData.string(forKey: "dns")
            let remoteIp = self.sharedData.string(forKey: "remoteIp")

            self.onAllocEvent(remoteIp,ip:ip, dns: dns, routes: "")
        case .connecting:
            print("vpn connecting")
        case .reasserting:
            print("vpn reconnecting")
            self.onReconnectingEvent()
        case .disconnecting:
            print("vpn disconnecting")
        case .disconnected, .invalid:
            
            let err = self.sharedData.string(forKey: "error")
            
            if err != nil && err != "" {
                self.onErrorEvent("system", errmsg: err)
            }
            
            self.onStoppedEvent()
        @unknown default:
            print("vpn status unkown")
        }
    }
    
    func addVPNStatusObserver() {
        
        guard observerAdded == false else { return }
        
        observerAdded = true
        loadProviderManager { [unowned self] (manager) -> Void in
             if let manager = manager {
                 NotificationCenter.default.addObserver(forName: NSNotification.Name.NEVPNStatusDidChange, object: manager.connection, queue: OperationQueue.main, using: { [unowned self] (notification) -> Void in
                     self.updateVPNStatus(manager)
                     })
             }
         }
     }
    
    func loadProviderManager(_ complete: @escaping (NETunnelProviderManager?) -> Void){
        NETunnelProviderManager.loadAllFromPreferences { (managers, error) in
            if let managers = managers {
                if managers.count > 0 {
                    let manager = managers[0]
                    complete(manager)
                    return
                }
            }
            complete(nil)
        }
    }
    
    func startVPN(options:[String:NSObject]) {
        
        NETunnelProviderManager.loadAllFromPreferences { (managers,error) in
            guard let managers = managers else{ return }
            let manager: NETunnelProviderManager
            if managers.count > 0 {
                manager = managers[0]
                
                do{
                    try manager.connection.startVPNTunnel(options:options)
                }catch let err{
                    print("start vpn fail",err)
                    self.onErrorEvent("system", errmsg: err.localizedDescription)
                    self.onStoppedEvent()
                    return
                }
                
                self.addVPNStatusObserver()

                
            }else{
                manager = self.makeManager()
                manager.saveToPreferences{ (error) in
                    
                    if error != nil {
                        print("save vpn fail,",error!)
                        self.onErrorEvent("system", errmsg: error?.localizedDescription)
                        self.onStoppedEvent()
                        return
                    }
                    
                    self.loadProviderManager{ (manager) in
                        
                        self.observerAdded = false
                        
                        guard manager != nil  else { return }
                        
                        do{
                            try manager!.connection.startVPNTunnel(options:options)
                        }catch let err{
                            self.onErrorEvent("system", errmsg: err.localizedDescription)
                            self.onStoppedEvent()
                            return
                        }
                        self.addVPNStatusObserver()
                    }
                }
            }
        }
    }

    func stopVPN() {
        
        NETunnelProviderManager.loadAllFromPreferences { (managers,error) in
            guard let managers = managers else{ return }

            if managers.count < 1 {
                return
            }
            managers[0].connection.stopVPNTunnel()
            
        }
    }

}


