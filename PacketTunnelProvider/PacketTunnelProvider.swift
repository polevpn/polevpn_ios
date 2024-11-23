//
//  PacketTunnelProvider.swift
//  PacketTunnelProvider
//
//  Created by polevpn on 30/11/22.
//


import NetworkExtension
import Polevpnmobile
import SwiftyJSON
import CommonCrypto
import os.log


public extension String {
    /* ################################################################## */
    /**
     - returns: the String, as an MD5 hash.
     */
    var md5: String {
        let str = self.cString(using: String.Encoding.utf8)
        let strLen = CUnsignedInt(self.lengthOfBytes(using: String.Encoding.utf8))
        let digestLen = Int(CC_MD5_DIGEST_LENGTH)
        let result = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: digestLen)
        CC_MD5(str!, strLen, result)

        let hash = NSMutableString()

        for i in 0..<digestLen {
            hash.appendFormat("%02x", result[i])
        }

        result.deallocate()
        return hash as String
    }
}

struct ApplicationMemoryCurrentUsage{
    
    var usage : Double = 0.0
    var total : Double = 0.0
    var ratio : Double = 0.0
    
}

func report_memory()->ApplicationMemoryCurrentUsage {
    var info = mach_task_basic_info()
    var count = mach_msg_type_number_t(MemoryLayout<mach_task_basic_info>.size)/4
    
    let kerr: kern_return_t = withUnsafeMutablePointer(to: &info) {
        $0.withMemoryRebound(to: integer_t.self, capacity: 1) {
            task_info(mach_task_self_,
                      task_flavor_t(MACH_TASK_BASIC_INFO),
                      $0,
                      &count)
        }
    }
    
    if kerr == KERN_SUCCESS {
        
        PolevpnmobileLog("info","Memory in use (in bytes): \(info.resident_size)")
        let usage = info.resident_size / (1024 * 1024)
        let total = ProcessInfo.processInfo.physicalMemory / (1024 * 1024)
        let ratio = Double(info.virtual_size) / Double(ProcessInfo.processInfo.physicalMemory)
        return ApplicationMemoryCurrentUsage(usage: Double(usage), total: Double(total), ratio: Double(ratio))
    }
    else {
        print("Error with task_info(): " +
              (String(cString: mach_error_string(kerr), encoding: String.Encoding.ascii) ?? "unknown error"))
        return ApplicationMemoryCurrentUsage()
    }
}

class PacketTunnelProvider:NEPacketTunnelProvider,PolevpnmobilePoleVPNEventHandlerProtocol ,PolevpnmobilePoleVPNLogHandlerProtocol {
    
    private let log = OSLog(subsystem: "polevpn-tunnel", category: "default")
    private var polevpn: PolevpnmobilePoleVPN!
    private var pendingCompletionStart: ((Error?) -> Void)?
    private var pendingCompletionStop: (() -> Void)?
    private var sharedData:UserDefaults!
    private var timer:DispatchSourceTimer!
    private var useRemoteRouteRules:Bool!
    private var localRules:[NEIPv4Route]!

    func onStoppedEvent() {
        
        PolevpnmobileLog("info","vpn stopped")
        
        self.flushData()
        
        if self.pendingCompletionStop != nil {
            self.pendingCompletionStop!()
        }
    }
    
    func onStartedEvent() {
        PolevpnmobileLog("info","vpn started")
    }

    
    func onReconnectedEvent() {
        PolevpnmobileLog("info","vpn connected")
        self.reasserting = false
    }
    
    func onReconnectingEvent() {
        PolevpnmobileLog("info","vpn reconnecting")
        self.reasserting = true
    }
    
    func onAllocEvent(_ ip: String?, dns: String?, routes: String?) {
        
        PolevpnmobileLog("info","vpn allocated ip="+ip!+",dns="+dns!+",routes="+routes!)

        let networkSettings = self.initTunnelSettings(remoteip: self.polevpn.getRemoteIP(),ip: ip!, dns: dns!, remoteRoutes:routes!)

        setTunnelNetworkSettings(networkSettings){
            error in
            guard error == nil else{
                PolevpnmobileLog("error","set networking settings fail,"+error!.localizedDescription)
                self.pendingCompletionStart!(error)
                return
            }
        }
        
        sharedData.setValue(self.polevpn.getRemoteIP(), forKey: "remoteIp")
        sharedData.setValue(ip, forKey: "ip")
        sharedData.setValue(dns, forKey: "dns")
        sharedData.synchronize()
        
        polevpn.attachIos(Int(getFd()))
        
        sharedData.setValue("", forKey: "error")
        sharedData.synchronize()
                
        self.pendingCompletionStart?(nil)

        
    }
    
    func onErrorEvent(_ errtype: String?, errmsg: String?) {
        PolevpnmobileLog("error","vpn error,"+errmsg!)
        sharedData.setValue(errmsg, forKey: "error")
        sharedData.synchronize()
        self.flushData()
        self.pendingCompletionStart!(NSError(domain: errmsg!, code: 1000))
    }
    
    func onWrite(_ data: String?) {
        os_log("%{public}s", log: log, type: .default, data!)
    }
    
    @objc private func flushData() {
        
        report_memory()
        sharedData.setValue(polevpn.getUpBytes(), forKey: "upBytes")
        sharedData.setValue(polevpn.getDownBytes(), forKey: "downBytes")
        
        sharedData.setValue(PolevpnmobileGetAllLogs(), forKey: "logs")
        
        sharedData.synchronize()

    }
    
    private func getFd() -> Int32 {
        if #available(iOS 15, *) {
            var buf = [CChar](repeating: 0, count: Int(IFNAMSIZ))
            let utunPrefix = "utun".utf8CString.dropLast()
            return (0...1024).first {
                (_ fd: Int32) -> Bool in
                var len = socklen_t(buf.count)
                return getsockopt(fd, 2, 2, &buf, &len) == 0 && buf.starts(with: utunPrefix)
            }!
        }
        
        return packetFlow.value(forKeyPath: "socket.fileDescriptor") as! Int32
    }
    
    override init() {
        super.init()
        self.sharedData = UserDefaults(suiteName: "group.com.polevpn.ios")
        PolevpnmobileSetLogHandler(self)
        
        self.polevpn = PolevpnmobilePoleVPN()
        self.polevpn.setEventHandler(self)

        
        let paths = NSSearchPathForDirectoriesInDomains(.documentDirectory, .userDomainMask, true)
        let documentPath = paths[0]
        PolevpnmobileSetLogPath(documentPath)
        PolevpnmobileSetLogLevel("INFO")
        
        self.timer = DispatchSource.makeTimerSource(flags: [], queue: DispatchQueue.global())
        self.timer.schedule(deadline: DispatchTime.now()+10, repeating: .seconds(10), leeway: .nanoseconds(1))
        
        self.timer.setEventHandler{
            self.flushData()
        }
        self.timer.activate()
        
    }
    
    deinit{
        if timer != nil {
            timer.cancel()
        }
    }
    

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        
        self.pendingCompletionStart = completionHandler
        
        let endpoint = options!["endpoint"] as! String
        let user = options!["user"] as! String
        let pwd = options!["pwd"] as! String
        let sni = options!["sni"] as! String
        let skipSSLVerify = options!["skipSSLVerify"] as! Bool
        self.useRemoteRouteRules = options!["useRemoteRouteRules"] as? Bool
        
        let localRouteRules = options!["localRouteRules"] as! String
        let proxyDomains = options!["proxyDomains"] as! String

        self.localRules = []
        if localRouteRules != "" {
            let ar = localRouteRules.components(separatedBy: "\n")
            for item in ar {
                let mask = PolevpnmobileGetSubNetMask(item)
                let ip = item.components(separatedBy: "/")[0]
                self.localRules.append( NEIPv4Route(destinationAddress: ip, subnetMask: mask))
            }
        }

        if proxyDomains != "" {
            let cidrs = PolevpnmobileGetRouteIpsFromDomain(proxyDomains)
            let ar = cidrs.components(separatedBy: "\n")
            for item in ar {

                let mask = PolevpnmobileGetSubNetMask(item)
                let ip = item.components(separatedBy: "/")[0]
                self.localRules.append( NEIPv4Route(destinationAddress: ip, subnetMask: mask))
            }
        }
        
        let deviceId = UIDevice.current.identifierForVendor?.uuidString
                        
        self.polevpn.start(endpoint, user: user,pwd: pwd,sni: sni,skipSSLVerify: skipSSLVerify,deviceType: "Ios",deviceId: deviceId?.md5)
    }
    
    
    private func initTunnelSettings(remoteip:String,ip:String,dns:String,remoteRoutes:String) -> NEPacketTunnelNetworkSettings {
        
        
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remoteip)

        settings.dnsSettings = NEDNSSettings(servers: [dns])
        let ipv4Settings = NEIPv4Settings(
           addresses: [ip],
           subnetMasks: ["255.255.255.255"]
        )
        

        
        var routeRules:[NEIPv4Route] = []
        var outputRules:[String] = []
        
        if self.useRemoteRouteRules {
            let remoteRouteRules =  JSON(parseJSON: remoteRoutes)
            let ar = remoteRouteRules.arrayValue
            
            for item in ar {
                var mask = PolevpnmobileGetSubNetMask(item.stringValue)
                var ip = item.stringValue.components(separatedBy: "/")[0]
                routeRules.append( NEIPv4Route(destinationAddress: ip, subnetMask: mask))
                outputRules.append(ip+":"+mask)

            }
        }
       
        for item in self.localRules {
            routeRules.append(item)
            outputRules.append(item.destinationAddress+":"+item.destinationSubnetMask)
        }
        
        PolevpnmobileLog("info","set route "+JSON(outputRules).rawString([:])!)
        
        ipv4Settings.includedRoutes = routeRules
        
        ipv4Settings.excludedRoutes = [
           NEIPv4Route(destinationAddress: remoteip, subnetMask: "255.255.255.255"),
        ]
        settings.ipv4Settings = ipv4Settings
        settings.mtu = 1500
        

        
        return settings
   }


    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        self.polevpn.stop()
        self.pendingCompletionStop = completionHandler
    }

}
