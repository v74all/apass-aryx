console.log("[*] Enhanced Asset Decryption Monitor - Runtime Asset Reading");

const CONFIG = {

    targetAssets: ['url.txt', 'port.txt', 'layout.bal', '.json', '.txt', '.bal', '.xml', '.properties'],

    bypassLibs: ['libxv1.so', 'xv1'],

    dumpAssets: true,
    dumpFolder: 'asset_dumps',

    waitForAppInit: 2000,   // ms to wait before hooking
    manualScanDelay: 5000,  // ms to wait before manual scan

    textDetectionThreshold: 0.7,
    previewLength: 200
};

Java.perform(function () {
    console.log("[*] Java.perform started for asset monitoring");

    const Logger = {
        INFO: '[INFO] ',
        WARN: '[WARN] ',
        ERROR: '[ERROR] ',
        SUCCESS: '[+] ',
        FAIL: '[-] ',
        ASSET: '[ASSET] ',
        DUMP: '[DUMP] ',
        BYPASS: '[BYPASS] ',
        NETWORK: '[🌐] ',
        MANUAL: '[MANUAL] ',
        
        info: function(msg) { console.log(this.INFO + msg); },
        warn: function(msg) { console.log(this.WARN + msg); },
        error: function(msg) { console.log(this.ERROR + msg); },
        success: function(msg) { console.log(this.SUCCESS + msg); },
        fail: function(msg) { console.log(this.FAIL + msg); },
        asset: function(msg) { console.log(this.ASSET + msg); },
        dump: function(msg) { console.log(this.DUMP + msg); },
        bypass: function(msg) { console.log(this.BYPASS + msg); },
        network: function(msg) { console.log(this.NETWORK + msg); },
        manual: function(msg) { console.log(this.MANUAL + msg); }
    };

    function bytesToString(bytes) {
        try {
            var StringCls = Java.use('java.lang.String');
            return StringCls.$new(bytes).toString();
        } catch (e) {
            return null;
        }
    }

    function isProbablyText(bytes) {
        try {
            var s = bytesToString(bytes);
            if (!s) return false;
            var printable = 0;
            var n = Math.min(s.length, 256);
            for (var i = 0; i < n; i++) {
                var c = s.charCodeAt(i);
                if (c === 0) return false;
                if ((c >= 9 && c <= 13) || (c >= 32 && c <= 126)) printable++;
            }
            return printable >= n * CONFIG.textDetectionThreshold;
        } catch (_) { return false; }
    }

    function isJsonData(str) {
        try {
            JSON.parse(str);
            return true;
        } catch (e) {
            return false;
        }
    }
    
    function analyzeContentType(bytes, filename) {
        const result = {
            type: 'unknown',
            isText: false,
            isJson: false,
            isXml: false,
            isConfig: false,
            containsUrls: false,
            containsPorts: false,
            preview: null,
            metadata: {}
        };

        result.isText = isProbablyText(bytes);
        if (result.isText) {
            const content = bytesToString(bytes);
            result.preview = content.replace(/\n/g, ' ').substring(0, CONFIG.previewLength);

            if (isJsonData(content)) {
                result.type = 'json';
                result.isJson = true;
                try {
                    const json = JSON.parse(content);
                    result.metadata.keys = Object.keys(json);
                } catch(e) {}
            } else if (content.trim().startsWith('<') && (content.includes('/>') || content.includes('</') || content.includes('xml'))) {
                result.type = 'xml';
                result.isXml = true;
            } else if (filename.endsWith('.properties') || content.includes('=') && !content.includes('{')) {
                result.type = 'config';
                result.isConfig = true;
            } else {
                result.type = 'text';
            }

            result.containsUrls = /https?:\/\//.test(content) || content.includes('://');
            result.containsPorts = /\b\d{2,5}\b/.test(content) && (content.includes('port') || content.includes('host'));

            if (content.includes('token') || content.includes('api') || content.includes('key')) {
                result.metadata.containsCredentials = true;
            }
        } else {

            result.type = 'binary';

            if (bytes.length > 2) {
                if (bytes[0] === 0x50 && bytes[1] === 0x4B) result.type = 'zip';
                else if (bytes[0] === 0x1F && bytes[1] === 0x8B) result.type = 'gzip';
                else if (bytes[0] === 0xFF && bytes[1] === 0xD8) result.type = 'jpeg';
                else if (bytes[0] === 0x89 && bytes[1] === 0x50) result.type = 'png';
            }
        }
        
        return result;
    }

    function ensureDir(path) {
        try {
            var File = Java.use('java.io.File');
            var f = File.$new(path);
            var parent = f.getParentFile();
            if (parent && !parent.exists()) parent.mkdirs();
        } catch (_) {}
    }

    function writeBytesTo(path, bytes) {
        if (!CONFIG.dumpAssets) return false;
        
        var FileOutputStream = Java.use('java.io.FileOutputStream');
        var fos = null;
        try {
            ensureDir(path);
            fos = FileOutputStream.$new(path);
            fos.write(bytes);
            fos.flush();
            Logger.dump('Wrote ' + bytes.length + ' bytes to ' + path);
            return true;
        } catch (e) {
            Logger.fail('Failed writing to ' + path + ': ' + e.message);
            return false;
        } finally {
            try { if (fos) fos.close(); } catch (_) {}
        }
    }

    function readAllBytes(inputStream) {
        var ByteArrayOutputStream = Java.use('java.io.ByteArrayOutputStream');
        var baos = ByteArrayOutputStream.$new();
        var arr = Java.array('byte', new Array(4096).fill(0));
        var read;
        while ((read = inputStream.read(arr)) !== -1) {
            baos.write(arr, 0, read);
        }
        var out = baos.toByteArray();
        try { baos.close(); } catch (_) {}
        return out;
    }

    function getAppExternalDir(subdir) {
        try {
            var ActivityThread = Java.use('android.app.ActivityThread');
            var app = ActivityThread.currentApplication();
            if (!app) return '/sdcard/Download';
            var ctx = app.getApplicationContext();
            var file = ctx.getExternalFilesDir(subdir);
            if (file) return file.getAbsolutePath();
        } catch (_) {}
        return '/sdcard/Download';
    }
    
    function generateDumpPath(assetName, type) {
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        const basePath = getAppExternalDir(CONFIG.dumpFolder);
        const category = type || 'assets_runtime';
        let sanitizedName = assetName.replace(/\//g, '_');
        
        return `${basePath}/${category}/${sanitizedName}`;
    }
    
    function isTargetAsset(assetName) {
        if (!assetName) return false;
        
        return CONFIG.targetAssets.some(target => {
            return target.startsWith('.') 
                ? assetName.endsWith(target) 
                : assetName === target || assetName.indexOf(target) !== -1;
        });
    }

    try {
        var LoaderClass = Java.use("xnotice.themainx.handler.Loader");
        LoaderClass.attach.implementation = function (param) {
            Logger.bypass("Loader.attach() called - providing dummy implementation");
            return;
        };
        LoaderClass.attachBaseContext.implementation = function (context) {
            Logger.bypass("Loader.attachBaseContext() called - calling parent but skipping native calls");
            var Application = Java.use("android.app.Application");
            Application.attachBaseContext.call(this, context);
            Logger.success("Successfully bypassed native library loading in attachBaseContext");
            return;
        };
        Logger.success("Library bypass hooks installed");
    } catch (e) {
        Logger.fail("Error installing bypass: " + e.message);
    }

    try {
        var System = Java.use("java.lang.System");
        System.load.overload('java.lang.String').implementation = function (filename) {
            if (filename && CONFIG.bypassLibs.some(lib => filename.indexOf(lib) !== -1)) {
                Logger.bypass("System.load intercepted: " + filename);
                return;
            }
            return this.load(filename);
        };
        System.loadLibrary.overload('java.lang.String').implementation = function (lib) {
            if (lib && CONFIG.bypassLibs.some(bypassLib => lib.indexOf(bypassLib) !== -1)) {
                Logger.bypass("System.loadLibrary intercepted: " + lib);
                return;
            }
            return this.loadLibrary(lib);
        };
        Logger.success("System library loading hooks installed");
    } catch (e) {
        Logger.fail("Error hooking System methods: " + e.message);
    }

    const assetStats = {
        accessed: {},
        interesting: [],
        
        recordAccess: function(assetName) {
            if (!this.accessed[assetName]) {
                this.accessed[assetName] = { 
                    count: 0, 
                    firstAccess: new Date(),
                    size: 0
                };
            }
            this.accessed[assetName].count++;
            this.accessed[assetName].lastAccess = new Date();
        },
        
        recordInteresting: function(assetName, metadata) {
            this.interesting.push({
                name: assetName,
                timestamp: new Date(),
                metadata: metadata
            });
        },
        
        summarize: function() {
            Logger.info("===== Asset Access Summary =====");
            Logger.info(`Total unique assets accessed: ${Object.keys(this.accessed).length}`);
            Logger.info(`Interesting assets found: ${this.interesting.length}`);
            
            if (this.interesting.length > 0) {
                Logger.info("\nInteresting assets:");
                this.interesting.forEach((item, idx) => {
                    Logger.info(`${idx+1}. ${item.name} - ${item.metadata.type} - ${item.metadata.preview || ''}`);
                });
            }
        }
    };

    setTimeout(function() {
        Logger.info("\n=== ASSET MANAGER MONITORING ===\n");

        try {
            var AssetManager = Java.use("android.content.res.AssetManager");
            
            AssetManager.open.overload('java.lang.String').implementation = function (filename) {
                var fname = filename ? filename.toString() : '';
                Logger.asset("Opening asset: " + fname);
                assetStats.recordAccess(fname);
                
                var inputStream = this.open(filename);
                
                if (isTargetAsset(fname)) {
                    try {
                        var bytes = readAllBytes(inputStream);
                        var analysis = analyzeContentType(bytes, fname);
                        var dumpPath = generateDumpPath(fname, 'assets_runtime');
                        
                        if (analysis.isText) {
                            Logger.asset(`${fname} (${analysis.type}) len=${bytes.length} preview="${analysis.preview}"`);

                            if (analysis.containsUrls || analysis.containsPorts || analysis.isJson || 
                                analysis.metadata.containsCredentials) {
                                assetStats.recordInteresting(fname, {
                                    type: analysis.type,
                                    preview: analysis.preview,
                                    size: bytes.length
                                });

                                dumpPath += `.${analysis.type}`;
                            }
                        } else {
                            Logger.asset(`${fname} len=${bytes.length} (${analysis.type})`);
                        }
                        
                        writeBytesTo(dumpPath, bytes);
                        
                        var ByteArrayInputStream = Java.use('java.io.ByteArrayInputStream');
                        return ByteArrayInputStream.$new(bytes);
                    } catch (e) {
                        Logger.fail('Error reading asset ' + fname + ': ' + e.message);
                    }
                }
                
                return inputStream;
            };

            AssetManager.open.overload('java.lang.String', 'int').implementation = function (filename, accessMode) {
                var fname = filename ? filename.toString() : '';
                Logger.asset("Opening asset with mode: " + fname + " (mode=" + accessMode + ")");
                assetStats.recordAccess(fname);
                
                var inputStream = this.open(filename, accessMode);
                
                if (isTargetAsset(fname)) {

                    try {
                        var bytes = readAllBytes(inputStream);
                        var analysis = analyzeContentType(bytes, fname);
                        var dumpPath = generateDumpPath(fname, 'assets_runtime');
                        
                        if (analysis.isText) {
                            Logger.asset(`${fname} (${analysis.type}) len=${bytes.length} preview="${analysis.preview}"`);
                            
                            if (analysis.containsUrls || analysis.containsPorts || analysis.isJson) {
                                assetStats.recordInteresting(fname, {
                                    type: analysis.type,
                                    preview: analysis.preview,
                                    size: bytes.length
                                });
                                dumpPath += `.${analysis.type}`;
                            }
                        } else {
                            Logger.asset(`${fname} len=${bytes.length} (${analysis.type})`);
                        }
                        
                        writeBytesTo(dumpPath, bytes);
                        
                        var ByteArrayInputStream = Java.use('java.io.ByteArrayInputStream');
                        return ByteArrayInputStream.$new(bytes);
                    } catch (e) {
                        Logger.fail('Error reading asset ' + fname + ': ' + e.message);
                    }
                }
                
                return inputStream;
            };
            
            Logger.success("AssetManager.open() hooked successfully");
        } catch (e) {
            Logger.fail("Error hooking AssetManager: " + e.message);
        }

        try {
            var InputStream = Java.use("java.io.InputStream");
            var originalRead = InputStream.read.overload('[B');
            
            InputStream.read.overload('[B').implementation = function (buffer) {
                var result = originalRead.call(this, buffer);

                if (result > 0) {
                    var content = "";
                    var isText = true;
                    
                    for (var i = 0; i < Math.min(result, 50); i++) {
                        var byte = buffer[i] & 0xFF;
                        if (byte >= 32 && byte <= 126) {
                            content += String.fromCharCode(byte);
                        } else if (byte === 0 || byte === 10 || byte === 13) {
                            content += ".";
                        } else {
                            isText = false;
                            break;
                        }
                    }

                    if (isText && (content.indexOf("http") !== -1 || 
                                  content.indexOf("://") !== -1 || 
                                  content.match(/\d{2,5}/) || 
                                  content.indexOf("port") !== -1 ||
                                  content.indexOf("url") !== -1)) {
                        Logger.network("Potential network config found in stream:");
                        Logger.network("   Content: " + content);
                    }
                }
                
                return result;
            };
            
            Logger.success("InputStream.read() hooked successfully");
        } catch (e) {
            Logger.fail("Error hooking InputStream: " + e.message);
        }

        setTimeout(function() {
            Logger.info("\n[🔍] Attempting manual asset reading...");
            
            try {
                var currentApplication = Java.use("android.app.ActivityThread").currentApplication();
                if (currentApplication) {
                    var context = currentApplication.getApplicationContext();
                    var assetManager = context.getAssets();

                    function listAndDump(prefix) {
                        try {
                            var list = assetManager.list(prefix);
                            for (var i = 0; i < list.length; i++) {
                                var name = list[i].toString();
                                var full = prefix ? (prefix + '/' + name) : name;

                                try {
                                    var sub = assetManager.list(full);
                                    if (sub && sub.length > 0) {
                                        listAndDump(full);
                                        continue;
                                    }
                                } catch (_) {}

                                if (!isTargetAsset(name)) continue;
                                try {
                                    var is = assetManager.open(full);
                                    var data = readAllBytes(is);
                                    try { is.close(); } catch (_) {}
                                    
                                    var analysis = analyzeContentType(data, full);
                                    var outPath = generateDumpPath(full, 'assets_manual');
                                    
                                    if (analysis.isText) {
                                        if (analysis.containsUrls || analysis.containsPorts || analysis.isJson) {
                                            outPath += `.${analysis.type}`;
                                            assetStats.recordInteresting(full, {
                                                type: analysis.type,
                                                preview: analysis.preview,
                                                size: data.length
                                            });
                                        }
                                        Logger.manual(`Dumped ${full} (${analysis.type}) len=${data.length} preview="${analysis.preview}"`);
                                    } else {
                                        Logger.manual(`Dumped ${full} len=${data.length} (${analysis.type})`);
                                    }
                                    
                                    writeBytesTo(outPath, data);
                                } catch (e) {
                                    Logger.fail('Error reading asset ' + full + ': ' + e.message);
                                }
                            }
                        } catch (e) {
                            Logger.fail('Error listing assets at ' + prefix + ': ' + e.message);
                        }
                    }

                    listAndDump('');

                    setTimeout(function() {
                        assetStats.summarize();
                    }, 1000);
                }
            } catch (e) {
                Logger.error("Error in manual asset reading: " + e.message);
            }
        }, CONFIG.manualScanDelay);

        Logger.info("\n=== ASSET MONITORING HOOKS INSTALLED ===\n");
        
    }, CONFIG.waitForAppInit);
});
