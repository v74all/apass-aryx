


'use strict';

console.log('[*] Attribution collector v2.0 loaded');

var report = {
  package: {},
  signing: {},
  firebase: {},
  network: { requests: [], tlsCerts: [], dnsQueries: [], userAgents: [] },
  environment: { 
    time: Date.now(),
    deviceInfo: {},
    systemProps: {},
    installedApps: [],
    runningProcesses: []
  },
  persistence: {
    services: [],
    receivers: [],
    autoStart: [],
    permissions: []
  },
  crypto: {
    wallets: [],
    algorithms: [],
    keys: []
  },
  behavior: {
    fileOperations: [],
    networkPatterns: [],
    antiAnalysis: [],
    ipcCommunication: []
  },
  threats: {
    c2Indicators: [],
    maliciousPatterns: [],
    evasionTechniques: []
  },
  clipboard: {
    captures: []
  },
  memory: {
    suspicious: []
  }
};

function safeStr(x) { try { return String(x); } catch (_) { return ''; } }

var WATCHLIST = [

  'ns.cjnp.lol', 'dwpb.foo',

  '1[1-9A-HJ-NP-Za-km-z]{25,34}', // Bitcoin
  '0x[a-fA-F0-9]{40}', // Ethereum

  'pastebin.com', 'paste.ee', 'hastebin.com', 'github.io',
  'herokuapp.com', 'appspot.com', 'firebaseio.com',

  'bit.ly', 'tinyurl.com', 'short.link', 'rebrand.ly',

  'api.telegram.org', 't.me/',

  'discord.com/api/webhooks',

  '.ir', 'naja.ir', 'police.ir',

  'googleapis.com', 'firebase', 'gstatic.com',

  'ngrok.io', 'serveo.net', 'localtunnel.me', 'dynamic-dns.net',

  '/jquery-3.3.1.min.js', '/jquery-3.3.2.min.js', '/jquery-3.2.2.min.js',

  '.onion', 'tor2web',

  'ransomware', 'ransom.', 'payment', 'unlock', 'decrypt',

  /[a-z0-9]{16,}\.com/, /[a-z0-9]{10,}\.io/
];

var CRYPTO_PATTERNS = [
  { name: 'Bitcoin', regex: /^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$/ },
  { name: 'Ethereum', regex: /^0x[a-fA-F0-9]{40}$/ },
  { name: 'Litecoin', regex: /^[LM3][a-km-zA-HJ-NP-Z1-9]{26,33}$/ },
  { name: 'Monero', regex: /^4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}$/ },

  { name: 'Ripple', regex: /^r[0-9a-zA-Z]{24,34}$/ },
  { name: 'Dogecoin', regex: /^D{1}[5-9A-HJ-NP-U]{1}[1-9A-HJ-NP-Za-km-z]{32}$/ },
  { name: 'Dash', regex: /^X[1-9A-HJ-NP-Za-km-z]{33}$/ },
  { name: 'Zcash', regex: /^z[a-zA-Z0-9]{94}$/ },
  { name: 'Cardano', regex: /^(addr1|Ae2)[a-zA-Z0-9]{54,104}$/ },
  { name: 'Tron', regex: /^T[A-Za-z1-9]{33}$/ }
];

var CONFIG = {
  maxRequestsPerReport: 200,
  maxDnsQueriesPerReport: 100,
  maxClipboardCapturesPerReport: 20,
  reportInterval: 30000, // 30 seconds
  memoryOptimization: true,
  enabledModules: {
    crypto: true,
    network: true,
    fileSystem: true,
    antiAnalysis: true,
    clipboard: true,
    sms: true,
    memory: true
  }
};

report.watchlist = WATCHLIST.slice(0);
report.watchHits = [];

function matchesWatchlist(str) {
  try {
    if (!str) return null;
    var s = safeStr(str).toLowerCase();
    for (var i = 0; i < WATCHLIST.length; i++) {
      if (typeof WATCHLIST[i] === 'string') {
        if (s.indexOf(WATCHLIST[i].toLowerCase()) !== -1) return WATCHLIST[i];
      } else if (WATCHLIST[i] instanceof RegExp) {
        if (WATCHLIST[i].test(s)) return WATCHLIST[i].toString();
      }
    }
  } catch (_) {}
  return null;
}

function detectCryptoWallet(str) {
  try {
    if (!str) return null;
    var s = safeStr(str);
    for (var i = 0; i < CRYPTO_PATTERNS.length; i++) {
      if (CRYPTO_PATTERNS[i].regex.test(s)) {
        return { type: CRYPTO_PATTERNS[i].name, address: s };
      }
    }
  } catch (_) {}
  return null;
}

function addThreatIndicator(type, indicator, context) {
  try {
    report.threats.c2Indicators.push({
      when: Date.now(),
      type: type,
      indicator: indicator,
      context: context || {}
    });
  } catch (_) {}
}

function collectDeviceFingerprint() {
  try {
    var app = Java.use('android.app.ActivityThread').currentApplication();
    var ctx = app.getApplicationContext();

    var Build = Java.use('android.os.Build');
    var SystemProperties = Java.use('android.os.SystemProperties');
    
    report.environment.deviceInfo = {
      manufacturer: safeStr(Build.MANUFACTURER.value),
      model: safeStr(Build.MODEL.value),
      brand: safeStr(Build.BRAND.value),
      device: safeStr(Build.DEVICE.value),
      board: safeStr(Build.BOARD.value),
      hardware: safeStr(Build.HARDWARE.value),
      serial: safeStr(Build.SERIAL.value),
      androidId: safeStr(android.provider.Settings.Secure.getString(ctx.getContentResolver(), "android_id")),
      release: safeStr(Build.VERSION.RELEASE.value),
      sdk: safeStr(Build.VERSION.SDK_INT.value),
      incremental: safeStr(Build.VERSION.INCREMENTAL.value),
      fingerprint: safeStr(Build.FINGERPRINT.value),
      bootloader: safeStr(Build.BOOTLOADER.value),
      tags: safeStr(Build.TAGS.value),
      type: safeStr(Build.TYPE.value),
      product: safeStr(Build.PRODUCT.value)
    };

    var sysProps = [
      "ro.build.description", "ro.build.display.id", "ro.build.id", 
      "ro.build.version.security_patch", "ro.crypto.state", "ro.crypto.type",
      "ro.debuggable", "ro.secure", "ro.product.cpu.abi", "ro.product.cpu.abilist",
      "ro.product.locale", "ro.hardware.keystore", "ro.boot.hardware", 
      "ro.boot.serialno", "ro.boot.verifiedbootstate", "ro.boot.flash.locked",
      "ro.boot.veritymode", "ro.bootmode", "ro.baseband"
    ];
    
    report.environment.systemProps = {};
    for (var i = 0; i < sysProps.length; i++) {
      report.environment.systemProps[sysProps[i]] = safeStr(SystemProperties.get(sysProps[i]));
    }

    var emulatorProps = [
      { prop: "ro.kernel.qemu", value: "1" },
      { prop: "ro.hardware", value: "goldfish" },
      { prop: "ro.hardware", value: "ranchu" },
      { prop: "ro.product.device", value: "generic" },
      { prop: "ro.product.model", value: "sdk" }
    ];
    
    report.environment.emulatorIndicators = [];
    for (var i = 0; i < emulatorProps.length; i++) {
      var val = SystemProperties.get(emulatorProps[i].prop);
      if (val && val.toString() === emulatorProps[i].value) {
        report.environment.emulatorIndicators.push({
          property: emulatorProps[i].prop,
          value: emulatorProps[i].value
        });
      }
    }

    var DisplayMetrics = Java.use('android.util.DisplayMetrics');
    var WindowManager = Java.use('android.view.WindowManager');
    var wm = ctx.getSystemService("window");
    var display = wm.getDefaultDisplay();
    var metrics = DisplayMetrics.$new();
    display.getMetrics(metrics);
    
    report.environment.deviceInfo.screen = {
      width: metrics.widthPixels.value,
      height: metrics.heightPixels.value,
      density: metrics.density.value,
      dpi: metrics.densityDpi.value,
      xdpi: metrics.xdpi.value,
      ydpi: metrics.ydpi.value
    };

    try {
      var TelephonyManager = Java.use('android.telephony.TelephonyManager');
      var tm = ctx.getSystemService("phone");
      report.environment.deviceInfo.telephony = {
        operator: safeStr(tm.getNetworkOperatorName()),
        operatorNumeric: safeStr(tm.getNetworkOperator()),
        country: safeStr(tm.getNetworkCountryIso()),
        simCountry: safeStr(tm.getSimCountryIso()),
        simOperator: safeStr(tm.getSimOperatorName()),
        simOperatorNumeric: safeStr(tm.getSimOperator()),
        phoneType: safeStr(tm.getPhoneType()),
        simState: safeStr(tm.getSimState()),
        dataActivity: safeStr(tm.getDataActivity()),
        dataState: safeStr(tm.getDataState())
      };
    } catch (e) {}

    try {
      var ConnectivityManager = Java.use('android.net.ConnectivityManager');
      var cm = ctx.getSystemService("connectivity");
      var activeNetwork = cm.getActiveNetworkInfo();
      if (activeNetwork) {
        report.environment.deviceInfo.network = {
          type: safeStr(activeNetwork.getTypeName()),
          subtype: safeStr(activeNetwork.getSubtypeName()),
          connected: activeNetwork.isConnected(),
          roaming: activeNetwork.isRoaming(),
          metered: cm.isActiveNetworkMetered(),
          extraInfo: safeStr(activeNetwork.getExtraInfo())
        };
      }

      report.environment.deviceInfo.networks = [];
      var allNetworks = cm.getAllNetworks();
      if (allNetworks) {
        for (var i = 0; i < allNetworks.length; i++) {
          var networkInfo = cm.getNetworkInfo(allNetworks[i]);
          if (networkInfo) {
            report.environment.deviceInfo.networks.push({
              type: safeStr(networkInfo.getTypeName()),
              subtype: safeStr(networkInfo.getSubtypeName()),
              connected: networkInfo.isConnected()
            });
          }
        }
      }
    } catch (e) {}

    try {
      var Intent = Java.use('android.content.Intent');
      var IntentFilter = Java.use('android.content.IntentFilter');
      var batteryIntent = ctx.registerReceiver(null, IntentFilter.$new("android.intent.action.BATTERY_CHANGED"));
      if (batteryIntent) {
        report.environment.deviceInfo.battery = {
          level: batteryIntent.getIntExtra("level", -1),
          scale: batteryIntent.getIntExtra("scale", -1),
          temperature: batteryIntent.getIntExtra("temperature", -1) / 10,
          voltage: batteryIntent.getIntExtra("voltage", -1),
          charging: batteryIntent.getIntExtra("status", -1) === 2,
          chargeType: batteryIntent.getIntExtra("plugged", -1)
        };
      }
    } catch (e) {}
    
  } catch (e) {
    console.log('[Attribution] device fingerprint failed: ' + e.message);
  }
}

function getExternalDir(subdir) {
  try {
    var ActivityThread = Java.use('android.app.ActivityThread');
    var app = ActivityThread.currentApplication();
    if (!app) return '/sdcard/Download';
    var ctx = app.getApplicationContext();
    var file = ctx.getExternalFilesDir(subdir);
    if (file) return file.getAbsolutePath();
  } catch (e) {}
  return '/sdcard/Download';
}

function writeText(path, text) {
  return Java.perform(function () {
    var FileOutputStream = Java.use('java.io.FileOutputStream');
    var StringCls = Java.use('java.lang.String');
    var fos = null;
    try {
      var File = Java.use('java.io.File');
      var f = File.$new(path);
      var parent = f.getParentFile();
      if (parent && !parent.exists()) parent.mkdirs();
      fos = FileOutputStream.$new(path);
      var jstr = StringCls.$new(text);
      var jbytes = jstr.getBytes();
      fos.write(jbytes);
      fos.flush();
      console.log('[Attribution] wrote report to ' + path);
    } catch (e) {
      console.log('[Attribution] write failed: ' + e.message);
    } finally { try { if (fos) fos.close(); } catch (_) {} }
  });
}

function finalizeReport() {
  try {

    report.analysis = {
      timestamp: Date.now(),
      threatScore: calculateThreatScore(),
      summary: generateThreatSummary(),
      recommendations: generateRecommendations()
    };

    if (CONFIG.memoryOptimization) {
      optimizeReportSize();
    }
    
    var outDir = getExternalDir('analysis');
    var timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    var path = outDir + '/enhanced_attribution_' + timestamp + '.json';
    writeText(path, JSON.stringify(report, null, 2));

    var iocPath = outDir + '/iocs_' + timestamp + '.txt';
    var iocContent = generateIOCList();
    writeText(iocPath, iocContent);

    var stixPath = outDir + '/stix_' + timestamp + '.json';
    var stixContent = generateSTIX();
    writeText(stixPath, stixContent);
    
    console.log('[Attribution] Enhanced report written to: ' + path);
    console.log('[Attribution] IOCs written to: ' + iocPath);
    console.log('[Attribution] STIX data written to: ' + stixPath);
    console.log('[Attribution] Threat Score: ' + report.analysis.threatScore + '/100');
  } catch (e) { 
    console.log('[Attribution] finalize failed: ' + e.message); 
  }
}

function optimizeReportSize() {
  try {
    if (report.network.requests.length > CONFIG.maxRequestsPerReport) {
      report.network.requests = report.network.requests.slice(-CONFIG.maxRequestsPerReport);
    }
    
    if (report.network.dnsQueries.length > CONFIG.maxDnsQueriesPerReport) {
      report.network.dnsQueries = report.network.dnsQueries.slice(-CONFIG.maxDnsQueriesPerReport);
    }
    
    if (report.clipboard && report.clipboard.captures && 
        report.clipboard.captures.length > CONFIG.maxClipboardCapturesPerReport) {
      report.clipboard.captures = report.clipboard.captures.slice(-CONFIG.maxClipboardCapturesPerReport);
    }
  } catch (e) {
    console.log('[Attribution] report optimization failed: ' + e.message);
  }
}

function generateSTIX() {
  try {
    var stixObj = {
      type: "bundle",
      id: "bundle--" + generateUUID(),
      spec_version: "2.0",
      objects: []
    };

    stixObj.objects.push({
      type: "malware",
      id: "malware--" + generateUUID(),
      created: new Date().toISOString(),
      modified: new Date().toISOString(),
      name: report.package.name || "unknown-malware",
      description: "Malware detected by enhanced attribution collector",
      malware_types: ["android", "mobile"]
    });

    report.network.requests.forEach(function(req) {
      try {
        var url = new URL(req.url);
        stixObj.objects.push({
          type: "indicator",
          id: "indicator--" + generateUUID(),
          created: new Date().toISOString(),
          modified: new Date().toISOString(),
          name: "Network request to " + url.hostname,
          description: "Network connection to suspicious domain",
          indicator_types: ["anomalous-activity"],
          pattern: "[domain-name:value = '" + url.hostname + "']",
          pattern_type: "stix"
        });
      } catch (_) {}
    });
    
    return JSON.stringify(stixObj, null, 2);
  } catch (e) {
    console.log('[Attribution] STIX generation failed: ' + e.message);
    return "{}";
  }
}

function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

function calculateThreatScore() {
  var score = 0;

  if (report.package.name && report.package.name.indexOf('xnotice') !== -1) score += 20;

  if (report.signing.certs) {
    report.signing.certs.forEach(function(cert) {
      if (cert.subject && cert.subject.indexOf('naja.ir') !== -1) score += 30; // Government cert
      if (cert.subject && cert.subject.indexOf('.ir') !== -1) score += 10; // Iranian cert
    });
  }

  if (report.watchHits.length > 0) score += report.watchHits.length * 10;
  if (report.network.requests.length > 50) score += 15; // High network activity

  if (report.crypto.wallets.length > 0) score += 25;

  if (report.persistence.services.length > 3) score += 15;

  if (report.behavior.antiAnalysis.length > 0) score += 20;

  var suspiciousFiles = report.behavior.fileOperations.filter(function(op) { return op.suspicious; });
  if (suspiciousFiles.length > 0) score += 15;

  if (report.behavior.ipcCommunication.length > 0) score += 20;

  if (report.clipboard.captures && report.clipboard.captures.length > 0) {
    var suspiciousClipboard = report.clipboard.captures.filter(function(c) { return c.suspicious; });
    if (suspiciousClipboard.length > 0) score += 15;
  }

  if (report.memory.suspicious && report.memory.suspicious.length > 0) {
    score += 25;
  }

  if (report.behavior.antiAnalysis.filter(function(a) { return a.type === 'emulator_check'; }).length > 0) {
    score += 20;
  }

  if (report.behavior.antiAnalysis.filter(function(a) { return a.type === 'root_check'; }).length > 0) {
    score += 10;
  }
  
  return Math.min(score, 100); // Cap at 100
}

function generateThreatSummary() {
  var summary = {
    category: 'Unknown',
    confidence: 'Low',
    capabilities: [],
    attribution: {}
  };
  
  var score = calculateThreatScore();
  
  if (score >= 80) {
    summary.category = 'Advanced Persistent Threat (APT)';
    summary.confidence = 'High';
  } else if (score >= 60) {
    summary.category = 'Spyware/Surveillance Tool';
    summary.confidence = 'Medium-High';
  } else if (score >= 40) {
    summary.category = 'Potentially Unwanted Program (PUP)';
    summary.confidence = 'Medium';
  } else if (score >= 20) {
    summary.category = 'Suspicious Application';
    summary.confidence = 'Low-Medium';
  }

  if (report.behavior.ipcCommunication.some(function(ipc) { return ipc.type === 'sms_send'; })) {
    summary.capabilities.push('SMS Exfiltration');
  }
  if (report.network.requests.length > 0) {
    summary.capabilities.push('Network Communication');
  }
  if (report.crypto.wallets.length > 0) {
    summary.capabilities.push('Cryptocurrency Theft');
  }
  if (report.behavior.antiAnalysis.length > 0) {
    summary.capabilities.push('Anti-Analysis Evasion');
  }
  if (report.behavior.fileOperations.some(function(op) { return op.suspicious; })) {
    summary.capabilities.push('Payload Dropping');
  }

  if (report.signing.certs && report.signing.certs.some(function(cert) { 
    return cert.subject && cert.subject.indexOf('naja.ir') !== -1; 
  })) {
    summary.attribution.country = 'Iran';
    summary.attribution.organization = 'NAJA (Iranian Police)';
    summary.attribution.confidence = 'High';
  }
  
  return summary;
}

function generateRecommendations() {
  var recommendations = [];
  
  var score = calculateThreatScore();
  
  if (score >= 70) {
    recommendations.push('IMMEDIATE: Isolate device from network');
    recommendations.push('IMMEDIATE: Wipe device and restore from clean backup');
    recommendations.push('URGENT: Change all passwords and authentication tokens');
  } else if (score >= 50) {
    recommendations.push('HIGH: Remove application immediately');
    recommendations.push('HIGH: Scan device with reputable anti-malware');
    recommendations.push('MEDIUM: Monitor network traffic for IOCs');
  } else if (score >= 30) {
    recommendations.push('MEDIUM: Remove suspicious application');
    recommendations.push('MEDIUM: Review and revoke unnecessary permissions');
    recommendations.push('LOW: Monitor device behavior');
  }
  
  if (report.crypto.wallets.length > 0) {
    recommendations.push('CRITICAL: Check cryptocurrency wallets for unauthorized transactions');
  }
  
  if (report.behavior.ipcCommunication.some(function(ipc) { return ipc.type === 'sms_send'; })) {
    recommendations.push('URGENT: Review SMS history and notify contacts of potential compromise');
  }
  
  return recommendations;
}

function generateIOCList() {
  var iocs = [];
  
  iocs.push('# Enhanced Attribution IOCs - Generated ' + new Date().toISOString());
  iocs.push('# Package Information');
  if (report.package.name) iocs.push('package_name:' + report.package.name);
  
  iocs.push('\n# Certificate Hashes');
  if (report.signing.certs) {
    report.signing.certs.forEach(function(cert) {
      iocs.push('cert_sha256:' + cert.sha256);
      iocs.push('cert_spki_sha256:' + cert.spkiSha256);
    });
  }
  
  iocs.push('\n# Network Indicators');
  report.network.requests.forEach(function(req) {
    try {
      var url = new URL(req.url);
      iocs.push('domain:' + url.hostname);
      if (url.pathname !== '/') iocs.push('url_path:' + url.pathname);
    } catch (_) {
      iocs.push('url:' + req.url);
    }
  });
  
  report.network.dnsQueries.forEach(function(dns) {
    iocs.push('dns_query:' + dns.host);
    iocs.push('ip_address:' + dns.ip);
  });
  
  iocs.push('\n# File System Indicators');
  report.behavior.fileOperations.forEach(function(op) {
    if (op.suspicious) {
      iocs.push('file_path:' + op.path);
    }
  });
  
  iocs.push('\n# Cryptocurrency Wallets');
  report.crypto.wallets.forEach(function(wallet) {
    iocs.push('crypto_wallet_' + wallet.type.toLowerCase() + ':' + wallet.address);
  });
  
  iocs.push('\n# Watchlist Hits');
  report.watchHits.forEach(function(hit) {
    iocs.push('watchlist_hit:' + hit.indicator + ' (' + hit.type + ')');
  });
  
  return iocs.join('\n');
}

Java.perform(function () {
  console.log('[Attribution] Starting enhanced collection v2.0...');

  collectDeviceFingerprint();

  monitorClipboard();
  monitorPermissions();
  monitorAntiAnalysis();
  monitorScreenCapture();

  try {
    var app = Java.use('android.app.ActivityThread').currentApplication();
    var ctx = app.getApplicationContext();
    var pm = ctx.getPackageManager();
    var pkg = ctx.getPackageName();
    var flags = 0x00000040; // GET_SIGNATURES deprecated on 28, but still returns on many
    try { flags = 0x00000040 | 0x00008000; } catch (_) {}
    var pi = pm.getPackageInfo(pkg, flags);
    report.package = {
      name: safeStr(pkg),
      versionName: safeStr(pi.versionName),
      versionCode: safeStr(pi.versionCode || (pi.getLongVersionCode ? pi.getLongVersionCode() : '')),
      installer: safeStr(pm.getInstallerPackageName(pkg)),
      firstInstallTime: safeStr(pi.firstInstallTime),
      lastUpdateTime: safeStr(pi.lastUpdateTime)
    };

    try {
      var MessageDigest = Java.use('java.security.MessageDigest');
      var CertificateFactory = Java.use('java.security.cert.CertificateFactory');
      var ByteArrayInputStream = Java.use('java.io.ByteArrayInputStream');
      var cf = CertificateFactory.getInstance('X.509');
      var md = MessageDigest.getInstance('SHA-256');
      var sigs = pi.signatures || (pi.signingInfo ? pi.signingInfo.getApkContentsSigners() : null);
      if (sigs) {
        var arr = [];
        for (var i = 0; i < sigs.length; i++) {
          var bytes = sigs[i].toByteArray();

          md.reset();
          var digest = md.digest(bytes);
          var hex = '';
          for (var j = 0; j < digest.length; j++) hex += (digest[j] & 0xff).toString(16).padStart(2, '0');

          var bais = ByteArrayInputStream.$new(bytes);
          var cert = cf.generateCertificate(bais);
          var X509Certificate = Java.use('java.security.cert.X509Certificate');
          cert = Java.cast(cert, X509Certificate);

          var subject = safeStr(cert.getSubjectX500Principal());
          var issuer = safeStr(cert.getIssuerX500Principal());
          var serial = safeStr(cert.getSerialNumber());
          var notBefore = safeStr(cert.getNotBefore());
          var notAfter = safeStr(cert.getNotAfter());

          var pub = cert.getPublicKey().getEncoded();
          md.reset();
          var spkiDigest = md.digest(pub);
          var spkiHex = '';
          for (var k = 0; k < spkiDigest.length; k++) spkiHex += (spkiDigest[k] & 0xff).toString(16).padStart(2, '0');

          arr.push({ index: i, sha256: hex, spkiSha256: spkiHex, subject: subject, issuer: issuer, serialNumber: serial, notBefore: notBefore, notAfter: notAfter });
        }
        report.signing = { certs: arr };
      }
    } catch (e) { report.signing.error = safeStr(e.message); }
  } catch (e) { console.log('[Attribution] package/signing failed: ' + e.message); }

  try {
    var Resources = Java.use('android.content.res.Resources');
    var r = ctx.getResources();
    function getStringByName(n) {
      try {
        var id = r.getIdentifier(n, 'string', report.package.name);
        if (id) return safeStr(r.getString(id));
      } catch (_) {}
      return null;
    }
    report.firebase.apiKey = getStringByName('google_api_key');
    report.firebase.projectId = getStringByName('gcm_defaultSenderId') || getStringByName('project_id');
    report.firebase.appId = getStringByName('google_app_id');
    report.firebase.databaseUrl = getStringByName('firebase_database_url');
    report.firebase.storageBucket = getStringByName('google_storage_bucket');
  } catch (e) { console.log('[Attribution] firebase probe failed: ' + e.message); }

  try {
    var FirebaseApp = Java.use('com.google.firebase.FirebaseApp');
    var FirebaseOptions = Java.use('com.google.firebase.FirebaseOptions');
    var apps = FirebaseApp.getApps();
    if (apps && apps.size() > 0) {
      var app0 = apps.get(0);
      var opts = app0.getOptions();
      report.firebase.appId = report.firebase.appId || safeStr(opts.getApplicationId());
      report.firebase.projectId = report.firebase.projectId || safeStr(opts.getProjectId());
      report.firebase.apiKey = report.firebase.apiKey || safeStr(opts.getApiKey());
      report.firebase.databaseUrl = report.firebase.databaseUrl || safeStr(opts.getDatabaseUrl());
      report.firebase.storageBucket = report.firebase.storageBucket || safeStr(opts.getStorageBucket());
    }
  } catch (e) {  }

  try {
    var FirebaseMessaging = Java.use('com.google.firebase.messaging.FirebaseMessaging');
    FirebaseMessaging.getToken.implementation = function () {
      var task = this.getToken();
      try {
        var OnSuccessListener = Java.use('com.google.android.gms.tasks.OnSuccessListener');
        var listener = Java.registerClass({
          name: 'com.copilot.TokenListener',
          implements: [OnSuccessListener],
          methods: {
            onSuccess: [{
              returnType: 'void',
              argumentTypes: ['java.lang.Object'],
              implementation: function (token) {
                try { report.firebase.fcmToken = safeStr(token); finalizeReport(); } catch (_) {}
              }
            }]
          }
        });
        task.addOnSuccessListener(listener.$new());
      } catch (_) {}
      return task;
    };
  } catch (e) {  }

  try {
    var Request = Java.use('okhttp3.Request');
    Request$Builder_init: {
      try {
        var Builder = Java.use('okhttp3.Request$Builder');
        Builder.build.implementation = function () {
          var req = this.build();
          try {
            var url = safeStr(req.url().toString());
            var method = safeStr(req.method());
            var headers = {};
            var hs = req.headers();
            var names = hs.names().toArray();
            for (var i = 0; i < names.length; i++) {
              var n = safeStr(names[i]);
              headers[n] = safeStr(hs.get(n));
            }
            report.network.requests.push({ when: Date.now(), url: url, method: method, headers: headers });
            var hit = matchesWatchlist(url);
            if (hit) {
              report.watchHits.push({ when: Date.now(), type: 'http', indicator: hit, url: url, method: method });
              finalizeReport();
            }
          } catch (_) {}
          return req;
        };
      } catch (e) {  }
    }
  } catch (e) { console.log('[Attribution] OkHttp hook failed: ' + e.message); }

  try {
    var OkHttpClient = Java.use('okhttp3.OkHttpClient');
    var originalNewCall = OkHttpClient.newCall.overload('okhttp3.Request');
    
    originalNewCall.implementation = function(request) {
      var call = originalNewCall.call(this, request);

      try {
        var originalExecute = call.execute;
        call.execute.implementation = function() {
          var response = originalExecute.call(this);
          try {
            var reqUrl = request.url().toString();
            var statusCode = response.code();
            var contentLength = response.body() ? response.body().contentLength() : -1;

            var responseEntry = {
              when: Date.now(),
              url: reqUrl,
              statusCode: statusCode,
              contentLength: contentLength,
              contentType: response.header("Content-Type", ""),
              server: response.header("Server", "")
            };
            
            if (!report.network.responses) {
              report.network.responses = [];
            }
            report.network.responses.push(responseEntry);

            if (statusCode === 302 || statusCode === 301) {
              var location = response.header("Location", "");
              var hit = matchesWatchlist(location);
              if (hit) {
                report.watchHits.push({ 
                  when: Date.now(), 
                  type: 'http_redirect', 
                  indicator: hit, 
                  url: reqUrl,
                  location: location
                });
              }
            }
          } catch (e) {
            console.log("[Attribution] Error processing response: " + e.message);
          }
          return response;
        };
      } catch (e) {
        console.log("[Attribution] Error hooking response: " + e.message);
      }
      
      return call;
    };
  } catch (e) {
    console.log("[Attribution] OkHttp response hook failed: " + e.message);
  }

  try {
    var InetAddress = Java.use('java.net.InetAddress');
    InetAddress.getByName.overload('java.lang.String').implementation = function (host) {
      var res = this.getByName(host);
      try { report.network.lastDns = { host: safeStr(host), ip: safeStr(res.getHostAddress()), when: Date.now() }; finalizeReport(); } catch (_) {}
      try {
        var hit = matchesWatchlist(host);
        if (hit) {
          report.watchHits.push({ when: Date.now(), type: 'dns', indicator: hit, host: safeStr(host), ip: safeStr(res.getHostAddress()) });
          finalizeReport();
        }
      } catch (_) {}
      return res;
    };
  } catch (e) {  }

  try {
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var TrustManagerImpl = null;
    try { TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl'); } catch (_) {}
    if (TrustManagerImpl) {
      var m = TrustManagerImpl.checkServerTrusted.overload('[Ljava.security.cert.X509Certificate;', 'java.lang.String', 'java.net.Socket');
      m.implementation = function (chain, authType, socket) {
        try {
          var arr = [];
          for (var i = 0; i < chain.length; i++) {
            var cert = chain[i];
            var subject = safeStr(cert.getSubjectDN());
            var issuer = safeStr(cert.getIssuerDN());
            arr.push({ subject: subject, issuer: issuer });
          }
          var peer = safeStr(socket && socket.getInetAddress());
          report.network.tlsCerts.push({ when: Date.now(), peer: peer, chain: arr });
          try {
            var hit = matchesWatchlist(peer);
            if (hit) {
              report.watchHits.push({ when: Date.now(), type: 'tls', indicator: hit, peer: peer });
            }
          } catch (_) {}
        } catch (_) {}
        return m.call(this, chain, authType, socket);
      };
    }
  } catch (e) { console.log('[Attribution] TLS hook failed: ' + e.message); }

  try {
    var WebSettings = Java.use('android.webkit.WebSettings');
    WebSettings.setUserAgentString.implementation = function (ua) {
      try {
        report.network.userAgents.push({ when: Date.now(), value: safeStr(ua) });
        var hit = matchesWatchlist(ua);
        if (hit) report.watchHits.push({ when: Date.now(), type: 'ua', indicator: hit, value: safeStr(ua) });
        finalizeReport();
      } catch (_) {}
      return this.setUserAgentString(ua);
    };
  } catch (e) {  }


  try {
    var File = Java.use('java.io.File');
    var FileOutputStream = Java.use('java.io.FileOutputStream');
    var FileInputStream = Java.use('java.io.FileInputStream');

    FileOutputStream.$init.overload('java.lang.String').implementation = function (path) {
      try {
        var pathStr = safeStr(path);
        report.behavior.fileOperations.push({
          when: Date.now(),
          operation: 'write',
          path: pathStr,
          suspicious: pathStr.indexOf('.so') !== -1 || pathStr.indexOf('dex') !== -1 || pathStr.indexOf('themainx') !== -1
        });
        if (pathStr.indexOf('.so') !== -1 || pathStr.indexOf('dex') !== -1) {
          addThreatIndicator('file_creation', 'native_library_drop', { path: pathStr });
        }
      } catch (_) {}
      return this.$init(path);
    };

    FileInputStream.$init.overload('java.lang.String').implementation = function (path) {
      try {
        var pathStr = safeStr(path);
        if (pathStr.indexOf('assets') !== -1 || pathStr.indexOf('.enc') !== -1) {
          report.behavior.fileOperations.push({
            when: Date.now(),
            operation: 'read',
            path: pathStr,
            type: 'asset_access'
          });
        }
      } catch (_) {}
      return this.$init(path);
    };
  } catch (e) {
    console.log('[Attribution] file monitoring failed: ' + e.message);
  }

  try {
    var ActivityManager = Java.use('android.app.ActivityManager');
    var am = ctx.getSystemService('activity');

    var services = am.getRunningServices(100);
    for (var i = 0; i < services.size(); i++) {
      var service = services.get(i);
      var serviceName = safeStr(service.service.getClassName());
      report.persistence.services.push({
        name: serviceName,
        pid: service.pid,
        uid: service.uid,
        foreground: service.foreground,
        started: service.started
      });
    }
  } catch (e) {
    console.log('[Attribution] service enumeration failed: ' + e.message);
  }

  try {
    var Cipher = Java.use('javax.crypto.Cipher');
    var originalDoFinal = Cipher.doFinal.overload('[B');
    originalDoFinal.implementation = function (input) {
      try {
        var result = originalDoFinal.call(this, input);
        var algorithm = safeStr(this.getAlgorithm());
        report.crypto.algorithms.push({
          when: Date.now(),
          algorithm: algorithm,
          inputSize: input.length,
          outputSize: result.length,
          operation: this.getOpmode()
        });

        var inputStr = '';
        var outputStr = '';
        try {
          inputStr = Java.use('java.lang.String').$new(input).toString();
          outputStr = Java.use('java.lang.String').$new(result).toString();
        } catch (_) {}
        
        var wallet = detectCryptoWallet(inputStr) || detectCryptoWallet(outputStr);
        if (wallet) {
          report.crypto.wallets.push({
            when: Date.now(),
            type: wallet.type,
            address: wallet.address,
            context: 'crypto_operation'
          });
          addThreatIndicator('crypto_wallet', wallet.type, { address: wallet.address });
        }
        
        return result;
      } catch (e) {
        return originalDoFinal.call(this, input);
      }
    };

    var KeyGenerator = Java.use('javax.crypto.KeyGenerator');
    KeyGenerator.generateKey.implementation = function() {
      var key = this.generateKey();
      try {
        report.crypto.keys.push({
          when: Date.now(),
          algorithm: this.getAlgorithm(),
          keySize: this.getKeySize ? this.getKeySize() : "unknown"
        });
      } catch (e) {}
      return key;
    };

    var KeyStore = Java.use('java.security.KeyStore');
    KeyStore.getKey.implementation = function(alias, password) {
      var key = this.getKey(alias, password);
      try {
        report.crypto.keys.push({
          when: Date.now(),
          operation: "keystore_access",
          alias: safeStr(alias),
          hasPassword: password != null
        });
      } catch (e) {}
      return key;
    };
    
  } catch (e) {
    console.log('[Attribution] crypto monitoring failed: ' + e.message);
  }

  try {
    var System = Java.use('java.lang.System');
    var originalLoad = System.load;
    var originalLoadLibrary = System.loadLibrary;
    
    System.load.implementation = function (filename) {
      try {
        var libPath = safeStr(filename);
        report.behavior.antiAnalysis.push({
          when: Date.now(),
          type: 'native_load',
          path: libPath,
          suspicious: libPath.indexOf('hidden') !== -1 || libPath.indexOf('themainx') !== -1
        });
        
        if (libPath.indexOf('xv1') !== -1 || libPath.indexOf('themainx') !== -1) {
          addThreatIndicator('anti_analysis', 'suspicious_library', { path: libPath });
        }
      } catch (_) {}
      return originalLoad.call(this, filename);
    };
    
    System.loadLibrary.implementation = function (libname) {
      try {
        var lib = safeStr(libname);
        report.behavior.antiAnalysis.push({
          when: Date.now(),
          type: 'library_load',
          name: lib
        });
      } catch (_) {}
      return originalLoadLibrary.call(this, libname);
    };
  } catch (e) {
    console.log('[Attribution] native library monitoring failed: ' + e.message);
  }

  try {
    var SmsManager = Java.use('android.telephony.SmsManager');
    SmsManager.sendTextMessage.overload('java.lang.String', 'java.lang.String', 'java.lang.String', 'android.app.PendingIntent', 'android.app.PendingIntent').implementation = function (dest, scAddr, text, sentIntent, deliveryIntent) {
      try {
        report.behavior.ipcCommunication.push({
          when: Date.now(),
          type: 'sms_send',
          destination: safeStr(dest),
          text: safeStr(text).substring(0, 100), // Truncate for privacy
          suspicious: true
        });
        addThreatIndicator('data_exfiltration', 'sms_send', { destination: safeStr(dest) });
      } catch (_) {}
      return this.sendTextMessage(dest, scAddr, text, sentIntent, deliveryIntent);
    };

    var Cursor = Java.use('android.database.Cursor');
    var ContentResolver = Java.use('android.content.ContentResolver');
    
    ContentResolver.query.overload('android.net.Uri', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String').implementation = function(uri, projection, selection, selectionArgs, sortOrder) {
      var cursor = this.query(uri, projection, selection, selectionArgs, sortOrder);
      try {
        var uriString = uri.toString();
        if (uriString.indexOf("content://sms") !== -1) {
          report.behavior.ipcCommunication.push({
            when: Date.now(),
            type: 'sms_read',
            uri: uriString,
            selection: safeStr(selection),
            suspicious: true
          });
          addThreatIndicator('data_exfiltration', 'sms_read', { uri: uriString });
        }
        
        if (uriString.indexOf("content://call_log") !== -1) {
          report.behavior.ipcCommunication.push({
            when: Date.now(),
            type: 'call_log_read',
            uri: uriString,
            selection: safeStr(selection),
            suspicious: true
          });
          addThreatIndicator('data_exfiltration', 'call_log_read', { uri: uriString });
        }
        
        if (uriString.indexOf("content://contacts") !== -1) {
          report.behavior.ipcCommunication.push({
            when: Date.now(),
            type: 'contacts_read',
            uri: uriString,
            selection: safeStr(selection),
            suspicious: true
          });
          addThreatIndicator('data_exfiltration', 'contacts_read', { uri: uriString });
        }
      } catch (e) {}
      return cursor;
    };
  } catch (e) {
    console.log('[Attribution] SMS monitoring failed: ' + e.message);
  }

  try {
    var Class = Java.use('java.lang.Class');
    var originalForName = Class.forName.overload('java.lang.String');
    originalForName.implementation = function (className) {
      try {
        var name = safeStr(className);
        if (name.indexOf('themainx') !== -1 || name.indexOf('xnotice') !== -1) {
          report.behavior.antiAnalysis.push({
            when: Date.now(),
            type: 'reflection',
            className: name,
            suspicious: true
          });
        }
      } catch (_) {}
      return originalForName.call(this, className);
    };
  } catch (e) {
    console.log('[Attribution] reflection monitoring failed: ' + e.message);
  }

  try {
    var InetAddress = Java.use('java.net.InetAddress');
    InetAddress.getByName.overload('java.lang.String').implementation = function (host) {
      var res = this.getByName(host);
      try {
        var hostStr = safeStr(host);
        var ipStr = safeStr(res.getHostAddress());
        
        report.network.dnsQueries.push({
          when: Date.now(),
          host: hostStr,
          ip: ipStr,
          suspicious: matchesWatchlist(hostStr) !== null
        });
        
        var hit = matchesWatchlist(hostStr);
        if (hit) {
          report.watchHits.push({ 
            when: Date.now(), 
            type: 'dns', 
            indicator: hit, 
            host: hostStr, 
            ip: ipStr 
          });
          addThreatIndicator('c2_communication', 'suspicious_dns', { host: hostStr, ip: ipStr });
        }

        if (hostStr.match(/^[a-f0-9]{8,}\./) || hostStr.includes('firebase') || hostStr.includes('appspot')) {
          report.threats.maliciousPatterns.push({
            when: Date.now(),
            type: 'c2_pattern',
            pattern: 'firebase_abuse',
            host: hostStr
          });
        }
        
        finalizeReport();
      } catch (_) {}
      return res;
    };
  } catch (e) {  }

  try {
    var Toast = Java.use('android.widget.Toast');
    Toast.makeText.overload('android.content.Context', 'java.lang.CharSequence', 'int').implementation = function (context, text, duration) {
      try {
        var message = safeStr(text);
        report.behavior.ipcCommunication.push({
          when: Date.now(),
          type: 'toast',
          message: message,
          duration: duration
        });
      } catch (_) {}
      return this.makeText(context, text, duration);
    };
  } catch (e) {
    console.log('[Attribution] toast monitoring failed: ' + e.message);
  }

  try {
    var packages = pm.getInstalledPackages(0);
    for (var i = 0; i < packages.size(); i++) {
      var pkg = packages.get(i);
      var appInfo = pkg.applicationInfo;
      report.environment.installedApps.push({
        packageName: safeStr(pkg.packageName),
        versionName: safeStr(pkg.versionName),
        versionCode: pkg.versionCode,
        flags: appInfo.flags,
        isSystemApp: (appInfo.flags & 1) !== 0, // FLAG_SYSTEM
        targetSdk: appInfo.targetSdkVersion
      });
    }
  } catch (e) {
    console.log('[Attribution] app enumeration failed: ' + e.message);
  }

  schedulePeriodicAnalysis();

  setTimeout(function () { 
    try { 
      console.log('[Attribution] Performing initial analysis...');
      performRealTimeAnalysis();
      performMemoryScan();
      finalizeReport(); 
    } catch (_) {} 
  }, 5000);

  var reportingInterval = setInterval(function() {
    finalizeReport();
  }, CONFIG.reportInterval);

  setTimeout(function () {
    try {
      clearInterval(reportingInterval);
      console.log('[Attribution] Analysis complete. Final threat score: ' + calculateThreatScore() + '/100');
    } catch (_) {}
  }, 300000); // Stop after 5 minutes
});

function performRealTimeAnalysis() {
  try {
    var currentScore = calculateThreatScore();

    if (currentScore >= 70 && !report.analysis.criticalAlertSent) {
      console.log('🚨 CRITICAL THREAT DETECTED - Score: ' + currentScore + '/100');
      console.log('🚨 Immediate action recommended!');
      report.analysis.criticalAlertSent = true;

      var criticalFindings = [];
      if (report.crypto.wallets.length > 0) criticalFindings.push('Cryptocurrency wallets detected');
      if (report.behavior.ipcCommunication.some(function(ipc) { return ipc.type === 'sms_send'; })) {
        criticalFindings.push('SMS exfiltration capability');
      }
      if (report.signing.certs && report.signing.certs.some(function(cert) { 
        return cert.subject && cert.subject.indexOf('naja.ir') !== -1; 
      })) {
        criticalFindings.push('Government-issued certificate (Iranian Police)');
      }
      
      console.log('🚨 Critical findings: ' + criticalFindings.join(', '));
    }

    var recentThreats = report.threats.c2Indicators.filter(function(threat) {
      return (Date.now() - threat.when) < 30000; // Last 30 seconds
    });
    
    if (recentThreats.length > 0) {
      console.log('⚠️  New threat indicators detected in last 30 seconds: ' + recentThreats.length);
      recentThreats.forEach(function(threat) {
        console.log('⚠️  ' + threat.type + ': ' + threat.indicator);
      });
    }

    var recentRequests = report.network.requests.filter(function(req) {
      return (Date.now() - req.when) < 60000; // Last minute
    });
    
    if (recentRequests.length > 10) {
      console.log('📡 High network activity detected: ' + recentRequests.length + ' requests in last minute');
      addThreatIndicator('network_pattern', 'high_frequency_requests', { count: recentRequests.length });
    }

    detectBeaconingActivity();

    analyzeProcessBehavior();
    
  } catch (e) {
    console.log('[Attribution] real-time analysis failed: ' + e.message);
  }
}

function detectBeaconingActivity() {
  try {

    var cutoff = Date.now() - 300000;
    var recentRequests = report.network.requests.filter(function(req) {
      return req.when >= cutoff;
    });

    var domains = {};
    recentRequests.forEach(function(req) {
      try {
        var url = new URL(req.url);
        var domain = url.hostname;
        if (!domains[domain]) {
          domains[domain] = [];
        }
        domains[domain].push(req.when);
      } catch (_) {}
    });

    for (var domain in domains) {
      if (domains[domain].length >= 3) {
        var times = domains[domain].sort();
        var intervals = [];
        for (var i = 1; i < times.length; i++) {
          intervals.push(times[i] - times[i-1]);
        }

        var avgInterval = intervals.reduce(function(a, b) { return a + b; }, 0) / intervals.length;
        var isRegular = intervals.every(function(interval) {

          return Math.abs(interval - avgInterval) / avgInterval < 0.2;
        });
        
        if (isRegular && intervals.length >= 2) {
          report.behavior.networkPatterns.push({
            when: Date.now(),
            type: 'beaconing',
            domain: domain,
            interval: Math.round(avgInterval),
            count: times.length
          });
          
          addThreatIndicator('c2_communication', 'beaconing_pattern', {
            domain: domain,
            interval: Math.round(avgInterval)
          });
        }
      }
    }
  } catch (e) {
    console.log('[Attribution] beaconing detection failed: ' + e.message);
  }
}

function analyzeProcessBehavior() {
  try {

    var hasSMSExfil = report.behavior.ipcCommunication.some(function(ipc) {
      return ipc.type === 'sms_send';
    });
    
    var hasWalletStealing = report.crypto.wallets.length > 0;
    
    var hasAntiAnalysis = report.behavior.antiAnalysis.length > 0;
    
    var hasC2Comms = report.threats.c2Indicators.length > 0;
    
    var hasClipboardMonitoring = report.clipboard.captures && 
                                 report.clipboard.captures.some(function(c) { return c.suspicious; });

    if ((hasSMSExfil && hasC2Comms) || 
        (hasWalletStealing && hasC2Comms) || 
        (hasClipboardMonitoring && hasC2Comms && hasAntiAnalysis)) {
      
      report.threats.maliciousPatterns.push({
        when: Date.now(),
        type: "combined_threat",
        indicators: {
          smsExfil: hasSMSExfil,
          walletStealing: hasWalletStealing,
          antiAnalysis: hasAntiAnalysis,
          c2Communication: hasC2Comms,
          clipboardMonitoring: hasClipboardMonitoring
        },
        severity: "critical"
      });
      
      console.log("🚨 CRITICAL: Multiple malicious behaviors detected in combination");
    }
  } catch (e) {
    console.log('[Attribution] process behavior analysis failed: ' + e.message);
  }
}
