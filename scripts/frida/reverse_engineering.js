console.log("[*] Starting enhanced reverse engineering script...");

var analysisState = {
    startTime: Date.now(),
    classCount: 0,
    methodCalls: 0,
    cryptoOps: 0,
    networkOps: 0,
    findings: []
};

function logWithCategory(category, level, message, data) {
    var timestamp = new Date().toISOString().split('T')[1].split('.')[0];
    var icon = {
        'INFO': 'ℹ️',
        'SUCCESS': '✅', 
        'ERROR': '❌',
        'WARNING': '⚠️',
        'CRYPTO': '🔐',
        'NETWORK': '🌐',
        'FILE': '📁',
        'CLASS': '📦',
        'MEMORY': '🧠'
    };
    
    console.log(`[${timestamp}] ${icon[level] || '📍'} [${category}] ${message}`);
    if (data) {
        console.log(`    📊 Data: ${JSON.stringify(data, null, 2)}`);
    }
}

Java.perform(function () {
    logWithCategory("INIT", "INFO", "Java.perform started for enhanced reverse engineering");

    try {
        var LoaderClass = Java.use("xnotice.themainx.handler.Loader");
        LoaderClass.attach.implementation = function (param) {
            logWithCategory("BYPASS", "SUCCESS", "Loader.attach() intercepted", {param: param});
            return;
        };
        LoaderClass.attachBaseContext.implementation = function (context) {
            logWithCategory("BYPASS", "SUCCESS", "Loader.attachBaseContext() intercepted");
            var Application = Java.use("android.app.Application");
            Application.attachBaseContext.call(this, context);
            logWithCategory("BYPASS", "SUCCESS", "Successfully bypassed native library loading");
            return;
        };
        logWithCategory("BYPASS", "SUCCESS", "Library bypass hooks installed");
    } catch (e) {
        logWithCategory("BYPASS", "ERROR", "Error installing bypass", {error: e.message, stack: e.stack});
    }

    try {
        var System = Java.use("java.lang.System");
        var Runtime = Java.use("java.lang.Runtime");
        
        System.load.overload('java.lang.String').implementation = function (filename) {
            logWithCategory("NATIVE", "INFO", "System.load called", {filename: filename});
            if (filename && (filename.indexOf("libxv1.so") !== -1 || filename.indexOf("xv1") !== -1)) {
                logWithCategory("NATIVE", "WARNING", "Target library load blocked", {filename: filename});
                analysisState.findings.push({type: "native_load_blocked", filename: filename, timestamp: Date.now()});
                return;
            }
            return this.load(filename);
        };
        
        System.loadLibrary.overload('java.lang.String').implementation = function (lib) {
            logWithCategory("NATIVE", "INFO", "System.loadLibrary called", {library: lib});
            if (lib && lib.indexOf("xv1") !== -1) {
                logWithCategory("NATIVE", "WARNING", "Target library loadLibrary blocked", {library: lib});
                analysisState.findings.push({type: "native_loadlibrary_blocked", library: lib, timestamp: Date.now()});
                return;
            }
            return this.loadLibrary(lib);
        };

        Runtime.exec.overload('java.lang.String').implementation = function (command) {
            logWithCategory("EXEC", "WARNING", "Runtime.exec detected", {command: command});
            analysisState.findings.push({type: "runtime_exec", command: command, timestamp: Date.now()});
            return this.exec(command);
        };
        
    } catch (e) {
        logWithCategory("NATIVE", "ERROR", "Error hooking System methods", {error: e.message});
    }

    function performClassAnalysis() {
        logWithCategory("ANALYSIS", "INFO", "Starting comprehensive class analysis");
        
        Java.enumerateLoadedClasses({
            onMatch: function(className) {
                if (className.indexOf("xnotice") !== -1 || 
                    className.indexOf("themainx") !== -1 ||
                    className.indexOf("crypto") !== -1 ||
                    className.indexOf("security") !== -1) {
                    
                    analysisState.classCount++;
                    logWithCategory("CLASS", "INFO", "Analyzing class", {className: className});
                    
                    try {
                        var clazz = Java.use(className);
                        var classInfo = {
                            name: className,
                            methods: [],
                            fields: [],
                            constructors: [],
                            superclass: null
                        };

                        var methods = clazz.class.getDeclaredMethods();
                        for (var i = 0; i < methods.length; i++) {
                            var method = methods[i];
                            var methodInfo = {
                                name: method.getName(),
                                returnType: method.getReturnType().getName(),
                                parameters: [],
                                modifiers: method.getModifiers()
                            };
                            
                            var params = method.getParameterTypes();
                            for (var j = 0; j < params.length; j++) {
                                methodInfo.parameters.push(params[j].getName());
                            }
                            
                            classInfo.methods.push(methodInfo);
                            logWithCategory("CLASS", "INFO", "Method found", {
                                class: className,
                                method: methodInfo.name,
                                signature: `${methodInfo.returnType} ${methodInfo.name}(${methodInfo.parameters.join(', ')})`
                            });
                        }

                        var fields = clazz.class.getDeclaredFields();
                        for (var i = 0; i < fields.length; i++) {
                            var field = fields[i];
                            var fieldInfo = {
                                name: field.getName(),
                                type: field.getType().getName(),
                                modifiers: field.getModifiers()
                            };
                            classInfo.fields.push(fieldInfo);
                            logWithCategory("CLASS", "INFO", "Field found", {
                                class: className,
                                field: fieldInfo.name,
                                type: fieldInfo.type
                            });
                        }

                        var superClass = clazz.class.getSuperclass();
                        if (superClass) {
                            classInfo.superclass = superClass.getName();
                            logWithCategory("CLASS", "INFO", "Inheritance found", {
                                class: className,
                                extends: classInfo.superclass
                            });
                        }
                        
                        analysisState.findings.push({type: "class_analysis", data: classInfo, timestamp: Date.now()});
                        
                    } catch (e) {
                        logWithCategory("CLASS", "ERROR", "Could not analyze class", {className: className, error: e.message});
                    }
                }
            },
            onComplete: function() {
                logWithCategory("ANALYSIS", "SUCCESS", "Class enumeration complete", {totalClasses: analysisState.classCount});
            }
        });
    }

    function setupCryptoMonitoring() {
        logWithCategory("CRYPTO", "INFO", "Setting up enhanced cryptographic monitoring");
        
        try {

            var Cipher = Java.use("javax.crypto.Cipher");

            Cipher.getInstance.overload('java.lang.String').implementation = function (algorithm) {
                logWithCategory("CRYPTO", "INFO", "Cipher.getInstance called", {algorithm: algorithm});
                analysisState.findings.push({type: "cipher_created", algorithm: algorithm, timestamp: Date.now()});
                return this.getInstance(algorithm);
            };

            Cipher.init.overload('int', 'java.security.Key').implementation = function (mode, key) {
                var modeStr = ["", "ENCRYPT_MODE", "DECRYPT_MODE", "WRAP_MODE", "UNWRAP_MODE"][mode] || mode;
                logWithCategory("CRYPTO", "INFO", "Cipher.init called", {
                    mode: modeStr,
                    keyAlgorithm: key.getAlgorithm(),
                    keyFormat: key.getFormat()
                });

                try {
                    var keyBytes = key.getEncoded();
                    if (keyBytes && keyBytes.length <= 32) {
                        var keyHex = "";
                        for (var i = 0; i < keyBytes.length; i++) {
                            keyHex += ("0" + (keyBytes[i] & 0xFF).toString(16)).slice(-2);
                        }
                        logWithCategory("CRYPTO", "WARNING", "Encryption key extracted", {
                            algorithm: key.getAlgorithm(),
                            keyHex: keyHex,
                            keyLength: keyBytes.length
                        });
                        analysisState.findings.push({type: "key_extracted", keyHex: keyHex, algorithm: key.getAlgorithm(), timestamp: Date.now()});
                    }
                } catch (e) {
                    logWithCategory("CRYPTO", "INFO", "Could not extract key bytes");
                }
                
                return this.init(mode, key);
            };

            Cipher.doFinal.overload('[B').implementation = function (input) {
                analysisState.cryptoOps++;
                var algorithm = this.getAlgorithm();
                logWithCategory("CRYPTO", "INFO", "Cipher operation", {
                    algorithm: algorithm,
                    inputLength: input.length,
                    operationCount: analysisState.cryptoOps
                });
                
                var result = this.doFinal(input);

                var inputHex = "";
                var outputHex = "";
                var previewLength = Math.min(32, input.length);
                
                for (var i = 0; i < previewLength; i++) {
                    inputHex += ("0" + (input[i] & 0xFF).toString(16)).slice(-2);
                }
                for (var i = 0; i < Math.min(32, result.length); i++) {
                    outputHex += ("0" + (result[i] & 0xFF).toString(16)).slice(-2);
                }
                
                logWithCategory("CRYPTO", "INFO", "Crypto operation result", {
                    algorithm: algorithm,
                    inputHex: inputHex + (input.length > 32 ? "..." : ""),
                    outputHex: outputHex + (result.length > 32 ? "..." : ""),
                    inputSize: input.length,
                    outputSize: result.length
                });
                
                analysisState.findings.push({
                    type: "crypto_operation",
                    algorithm: algorithm,
                    inputLength: input.length,
                    outputLength: result.length,
                    timestamp: Date.now()
                });
                
                return result;
            };

            var MessageDigest = Java.use("java.security.MessageDigest");
            MessageDigest.digest.overload('[B').implementation = function (input) {
                var algorithm = this.getAlgorithm();
                logWithCategory("CRYPTO", "INFO", "Hash operation", {
                    algorithm: algorithm,
                    inputLength: input.length
                });
                
                var result = this.digest(input);
                
                var inputHex = "";
                var outputHex = "";
                for (var i = 0; i < Math.min(16, input.length); i++) {
                    inputHex += ("0" + (input[i] & 0xFF).toString(16)).slice(-2);
                }
                for (var i = 0; i < result.length; i++) {
                    outputHex += ("0" + (result[i] & 0xFF).toString(16)).slice(-2);
                }
                
                logWithCategory("CRYPTO", "INFO", "Hash result", {
                    algorithm: algorithm,
                    inputHex: inputHex + (input.length > 16 ? "..." : ""),
                    hashHex: outputHex
                });
                
                return result;
            };
            
        } catch (e) {
            logWithCategory("CRYPTO", "ERROR", "Error setting up crypto monitoring", {error: e.message});
        }
    }

    function setupNetworkMonitoring() {
        logWithCategory("NETWORK", "INFO", "Setting up network monitoring");
        
        try {

            var URL = Java.use("java.net.URL");
            URL.openConnection.overload().implementation = function () {
                analysisState.networkOps++;
                logWithCategory("NETWORK", "INFO", "URL connection", {
                    url: this.toString(),
                    protocol: this.getProtocol(),
                    host: this.getHost(),
                    port: this.getPort()
                });
                
                analysisState.findings.push({
                    type: "network_connection",
                    url: this.toString(),
                    protocol: this.getProtocol(),
                    host: this.getHost(),
                    port: this.getPort(),
                    timestamp: Date.now()
                });
                
                return this.openConnection();
            };

            var HttpURLConnection = Java.use("java.net.HttpURLConnection");
            HttpURLConnection.getRequestMethod.implementation = function () {
                var method = this.getRequestMethod();
                logWithCategory("NETWORK", "INFO", "HTTP request", {
                    method: method,
                    url: this.getURL().toString()
                });
                return method;
            };

            var Socket = Java.use("java.net.Socket");
            Socket.$init.overload('java.lang.String', 'int').implementation = function (host, port) {
                logWithCategory("NETWORK", "INFO", "Socket connection", {
                    host: host,
                    port: port
                });
                
                analysisState.findings.push({
                    type: "socket_connection",
                    host: host,
                    port: port,
                    timestamp: Date.now()
                });
                
                return this.$init(host, port);
            };
            
        } catch (e) {
            logWithCategory("NETWORK", "ERROR", "Error setting up network monitoring", {error: e.message});
        }
    }

    function setupFileMonitoring() {
        logWithCategory("FILE", "INFO", "Setting up enhanced file monitoring");
        
        try {

            var FileInputStream = Java.use("java.io.FileInputStream");
            FileInputStream.$init.overload('java.lang.String').implementation = function (filename) {
                if (filename.indexOf("assets") !== -1 || 
                    filename.indexOf("themainx") !== -1 ||
                    filename.indexOf("cache") !== -1 ||
                    filename.indexOf("data") !== -1) {
                    logWithCategory("FILE", "INFO", "File access", {filename: filename});
                    analysisState.findings.push({type: "file_access", filename: filename, timestamp: Date.now()});
                }
                return this.$init(filename);
            };

            var AssetManager = Java.use("android.content.res.AssetManager");
            AssetManager.open.overload('java.lang.String').implementation = function (filename) {
                logWithCategory("FILE", "INFO", "Asset opened", {filename: filename});
                var result = this.open(filename);

                try {
                    var available = result.available();
                    if (available > 0 && available < 50000) {
                        var bytes = Java.array('byte', available);
                        result.read(bytes);

                        var contentType = "unknown";
                        var preview = "";
                        
                        if (bytes[0] == 0x7F && bytes[1] == 0x45 && bytes[2] == 0x4C && bytes[3] == 0x46) {
                            contentType = "ELF binary";
                        } else if (bytes[0] == 0x50 && bytes[1] == 0x4B) {
                            contentType = "ZIP/APK";
                        } else if (bytes[0] == 0xFF && bytes[1] == 0xD8) {
                            contentType = "JPEG image";
                        } else if (bytes[0] == 0x89 && bytes[1] == 0x50 && bytes[2] == 0x4E && bytes[3] == 0x47) {
                            contentType = "PNG image";
                        } else {

                            var isText = true;
                            for (var i = 0; i < Math.min(100, available); i++) {
                                var b = bytes[i] & 0xFF;
                                if (b < 32 && b != 9 && b != 10 && b != 13) {
                                    isText = false;
                                    break;
                                }
                                if (isText) {
                                    preview += String.fromCharCode(b);
                                }
                            }
                            if (isText) {
                                contentType = "text";
                            }
                        }
                        
                        logWithCategory("FILE", "INFO", "Asset content analyzed", {
                            filename: filename,
                            size: available,
                            type: contentType,
                            preview: preview.substring(0, 100)
                        });
                        
                        analysisState.findings.push({
                            type: "asset_content",
                            filename: filename,
                            size: available,
                            contentType: contentType,
                            preview: preview.substring(0, 100),
                            timestamp: Date.now()
                        });
                        
                        result.reset();
                    }
                } catch (e) {
                    logWithCategory("FILE", "WARNING", "Could not analyze asset content", {filename: filename, error: e.message});
                }
                
                return result;
            };
            
        } catch (e) {
            logWithCategory("FILE", "ERROR", "Error setting up file monitoring", {error: e.message});
        }
    }

    function setupMemoryMonitoring() {
        logWithCategory("MEMORY", "INFO", "Setting up memory monitoring");
        
        try {

            var System = Java.use("java.lang.System");
            System.gc.implementation = function () {
                logWithCategory("MEMORY", "INFO", "Garbage collection triggered");
                var runtime = Java.use("java.lang.Runtime").getRuntime();
                var totalMemory = runtime.totalMemory();
                var freeMemory = runtime.freeMemory();
                var usedMemory = totalMemory - freeMemory;
                
                logWithCategory("MEMORY", "INFO", "Memory stats", {
                    totalMemory: totalMemory,
                    freeMemory: freeMemory,
                    usedMemory: usedMemory,
                    usagePercent: Math.round((usedMemory / totalMemory) * 100)
                });
                
                return this.gc();
            };
            
        } catch (e) {
            logWithCategory("MEMORY", "ERROR", "Error setting up memory monitoring", {error: e.message});
        }
    }

    function generateAnalysisReport() {
        var endTime = Date.now();
        var duration = endTime - analysisState.startTime;
        
        logWithCategory("REPORT", "INFO", "=== ANALYSIS REPORT ===");
        logWithCategory("REPORT", "INFO", "Analysis duration", {durationMs: duration, durationSec: (duration/1000).toFixed(2)});
        logWithCategory("REPORT", "INFO", "Statistics", {
            classesAnalyzed: analysisState.classCount,
            methodCalls: analysisState.methodCalls,
            cryptoOperations: analysisState.cryptoOps,
            networkOperations: analysisState.networkOps,
            totalFindings: analysisState.findings.length
        });

        var findingsByType = {};
        for (var i = 0; i < analysisState.findings.length; i++) {
            var finding = analysisState.findings[i];
            if (!findingsByType[finding.type]) {
                findingsByType[finding.type] = [];
            }
            findingsByType[finding.type].push(finding);
        }
        
        logWithCategory("REPORT", "INFO", "Findings summary", findingsByType);

        var securityIssues = [];
        if (findingsByType.key_extracted && findingsByType.key_extracted.length > 0) {
            securityIssues.push("Encryption keys extracted from memory");
        }
        if (findingsByType.native_load_blocked && findingsByType.native_load_blocked.length > 0) {
            securityIssues.push("Native library loading detected and blocked");
        }
        if (findingsByType.runtime_exec && findingsByType.runtime_exec.length > 0) {
            securityIssues.push("Runtime command execution detected");
        }
        
        if (securityIssues.length > 0) {
            logWithCategory("SECURITY", "WARNING", "Security issues detected", securityIssues);
        } else {
            logWithCategory("SECURITY", "SUCCESS", "No major security issues detected");
        }
    }

    setTimeout(function() {
        logWithCategory("ANALYSIS", "INFO", "Starting comprehensive reverse engineering analysis");

        setupCryptoMonitoring();
        setupNetworkMonitoring();
        setupFileMonitoring();
        setupMemoryMonitoring();

        performClassAnalysis();

        setTimeout(function() {
            generateAnalysisReport();
            logWithCategory("ANALYSIS", "SUCCESS", "Reverse engineering analysis complete");
        }, 5000);
        
    }, 2000);

    setInterval(function() {
        logWithCategory("STATUS", "INFO", "Analysis status", {
            runtime: ((Date.now() - analysisState.startTime) / 1000).toFixed(1) + "s",
            findings: analysisState.findings.length,
            cryptoOps: analysisState.cryptoOps,
            networkOps: analysisState.networkOps
        });
    }, 30000);
});
