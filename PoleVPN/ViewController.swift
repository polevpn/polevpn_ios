//
//  ViewController.swift
//  wkwebview
//

import UIKit
import WebKit
import Polevpnmobile
import SwiftyJSON

class ViewController: UIViewController, WKNavigationDelegate, WKScriptMessageHandler,PolevpnmobilePoleVPNEventHandlerProtocol {
    
    var webView: WKWebView!
    var polevpn: PolevpnmobilePoleVPN!
    
    override func loadView() {
        webView = WKWebView()
        webView.navigationDelegate = self
        webView.configuration.userContentController.add(self, name: "ext")
        view = webView
        
        let homePath = NSHomeDirectory()
                
        var err:NSError?
        
        PolevpnmobileInitDB(homePath+"/config.db",&err)
        PolevpnmobileSetLogPath(homePath)
        
        polevpn = PolevpnmobilePoleVPN()
        polevpn.setEventHandler(self)
        
    }
    
    func userContentController(_ userContentController: WKUserContentController, didReceive message: WKScriptMessage) {
        
        print("message", message.body)
        
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
            let endpoint = msg["req"]["Endpoint"].stringValue
            let user = msg["req"]["User"].stringValue
            let pwd = msg["req"]["Password"].stringValue
            let sni = msg["req"]["Sni"].stringValue
            let skipSSLVerify = msg["req"]["SkipVerifySSL"].boolValue

            polevpn.start(endpoint, user: user, pwd: pwd, sni: sni, skipSSLVerify: skipSSLVerify)
            
            respJson(seq: seq, msg: "{'Msg':'ok','Code':0}")
            
        } else if name == "StopAccessServer" {
            polevpn.stop()
            respJson(seq: seq, msg: "{'Msg':'ok','Code':0}")

        }else if name == "GetAllLogs" {
            let logs = PolevpnmobileGetAllLogs()
            print("logs",logs)
            var msg = JSON()
            msg["event"] = "logs"
            msg["data"] = JSON()
            msg["data"]["logs"] = JSON(logs)

                    
            DispatchQueue.main.async {
                self.webView.evaluateJavaScript("onCallback("+msg.rawString([:])!+")")
                return
            }
            
            respJson(seq: seq, msg: "{'Msg':'ok','Code':0}")

        }else if name == "GetUpDownBytes" {
            let upBytes = polevpn.getUpBytes()
            let downBytes = polevpn.getDownBytes()
            
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
    }
    
    func onAllocEvent(_ ip: String?, dns: String?, routes: String?) {
        
        var msg = JSON()
        msg["event"] = "allocated"
        msg["data"] = JSON()
        msg["data"]["ip"] = JSON(ip!)
        msg["data"]["remoteIp"] = JSON(polevpn.getRemoteIP())
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


}


