console.log("[*] Starting comprehensive app analysis...");

(function() {
    'use strict';

    const analyzedItems = {
        urls: new Set(),
        cryptoAlgorithms: new Set(),
        databaseOperations: new Set(),
        fileOperations: new Set(),
        reflectiveAccess: new Set()
    };

    const config = {
        bypassEnabled: true,
        logLevel: 'info', // 'debug', 'info', 'warn', 'error'
        delayBeforeAnalysis: 3000
    };

    function logMessage(level, category, message) {
        const icons = {
            'debug': '🔍',
            'info': 'ℹ️',
            'warn': '⚠️',
            'error': '❌',
            'success': '✅',
            'bypass': '🛡️',
            'network': '🌐',
            'crypto': '🔐',
            'filesystem': '💾',
            'database': '🗄️',
            'permission': '🔓',
            'reflection': '🔄',
            'webview': '🌍',
            'native': '⚙️',
            'anti-analysis': '👁️'
        };
        
        const prefix = icons[category] || icons[level] || '';
        console.log(`[${prefix} ${category.toUpperCase()}] ${message}`);
    }

    function bytesToHex(bytes) {
        let hex = '';
        for (let i = 0; i < bytes.length; i++) {
            const byte = bytes[i] & 0xff;
            hex += ('00' + byte.toString(16)).slice(-2);
        }
        return hex;
    }

    function installBypassHooks() {
        if (!config.bypassEnabled) return;
        
        Java.perform(function() {
            logMessage('info', 'bypass', 'Installing security bypass hooks');

            try {
                var LoaderClass = Java.use("xnotice.themainx.handler.Loader");
                LoaderClass.attach.implementation = function(param) {
                    logMessage('info', 'bypass', 'Bypassed Loader.attach()');
                    return;
                };
                
                LoaderClass.attachBaseContext.implementation = function(context) {
                    logMessage('info', 'bypass', 'Bypassing Loader.attachBaseContext()');
                    var Application = Java.use("android.app.Application");
                    Application.attachBaseContext.call(this, context);
                    logMessage('success', 'bypass', 'Successfully bypassed native library loading');
                    return;
                };
            } catch (e) {
                logMessage('error', 'bypass', 'Error installing Loader bypass: ' + e.message);
            }

            try {
                var System = Java.use("java.lang.System");
                System.load.overload('java.lang.String').implementation = function(filename) {
                    if (filename) {
                        if (filename.indexOf("libxv1.so") !== -1 || filename.indexOf("xv1") !== -1) {
                            logMessage('info', 'bypass', 'Blocked native library: ' + filename);
                            return;
                        }
                        logMessage('debug', 'native', 'Library loaded: ' + filename);
                    }
                    return this.load(filename);
                };
                
                System.loadLibrary.overload('java.lang.String').implementation = function(lib) {
                    if (lib) {
                        if (lib.indexOf("xv1") !== -1) {
                            logMessage('info', 'bypass', 'Blocked library: ' + lib);
                            return;
                        }
                        logMessage('debug', 'native', 'Library loaded: ' + lib);
                    }
                    return this.loadLibrary(lib);
                };
            } catch (e) {
                logMessage('error', 'bypass', 'Error hooking System methods: ' + e.message);
            }

            try {

                var Runtime = Java.use('java.lang.Runtime');
                Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
                    logMessage('debug', 'anti-analysis', 'Runtime.exec called with: ' + cmd);
                    if (cmd.indexOf("su") !== -1 || cmd.indexOf("which") !== -1 && cmd.indexOf("su") !== -1) {
                        logMessage('info', 'bypass', 'Bypassing root check command: ' + cmd);
                        return Runtime.exec.call(this, "echo");
                    }
                    return this.exec(cmd);
                };
            } catch (e) {
                logMessage('error', 'bypass', 'Error installing root detection bypass: ' + e.message);
            }

            try {
                var Build = Java.use('android.os.Build');
                var deviceProperties = [
                    { field: 'BRAND', value: 'samsung' },
                    { field: 'MANUFACTURER', value: 'samsung' },
                    { field: 'MODEL', value: 'SM-G991B' },
                    { field: 'PRODUCT', value: 'o1q' },
                    { field: 'DEVICE', value: 'o1q' },
                    { field: 'HARDWARE', value: 'qcom' }
                ];
                
                deviceProperties.forEach(prop => {
                    try {
                        const fieldValue = Build[prop.field].value;
                        logMessage('debug', 'anti-analysis', `Original ${prop.field}: ${fieldValue}`);

                        if (fieldValue && (fieldValue.toLowerCase().indexOf('emulator') !== -1 || 
                                          fieldValue.toLowerCase().indexOf('generic') !== -1 ||
                                          fieldValue.toLowerCase().indexOf('sdk') !== -1)) {
                            Build[prop.field].value = prop.value;
                            logMessage('info', 'bypass', `Spoofed ${prop.field} to: ${prop.value}`);
                        }
                    } catch (e) {
                        logMessage('error', 'bypass', `Error spoofing ${prop.field}: ${e.message}`);
                    }
                });
            } catch (e) {
                logMessage('error', 'bypass', 'Error installing emulator detection bypass: ' + e.message);
            }
        });
    }

    function analyzePackageInfo() {
        Java.perform(function() {
            logMessage('info', 'info', '📱 APP SPECIFICATIONS');
            
            try {
                var context = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
                var packageManager = context.getPackageManager();
                var packageName = context.getPackageName();
                var packageInfo = packageManager.getPackageInfo(packageName, 0);
                
                logMessage('info', 'info', 'Package: ' + packageName);
                logMessage('info', 'info', 'Version Code: ' + packageInfo.versionCode.value);
                logMessage('info', 'info', 'Version Name: ' + packageInfo.versionName.value);
                logMessage('info', 'info', 'Target SDK: ' + packageInfo.applicationInfo.value.targetSdkVersion.value);
                logMessage('info', 'info', 'Min SDK: ' + packageInfo.applicationInfo.value.minSdkVersion.value);

                try {
                    var PackageManager = Java.use("android.content.pm.PackageManager");
                    var GET_SIGNATURES = PackageManager.GET_SIGNATURES.value;
                    var packageInfoSig = packageManager.getPackageInfo(packageName, GET_SIGNATURES);
                    var signatures = packageInfoSig.signatures.value;
                    
                    if (signatures.length > 0) {
                        var MessageDigest = Java.use("java.security.MessageDigest");
                        var md = MessageDigest.getInstance("SHA-256");
                        var digest = md.digest(signatures[0].toByteArray());
                        var hexString = bytesToHex(digest);
                        logMessage('info', 'info', 'Signature SHA-256: ' + hexString.toUpperCase());
                    }
                } catch (e) {
                    logMessage('error', 'info', 'Could not get signature: ' + e.message);
                }
            } catch (e) {
                logMessage('error', 'info', 'Error getting package info: ' + e.message);
            }
        });
    }

    function monitorNetworkActivity() {
        Java.perform(function() {
            logMessage('info', 'network', '🌐 NETWORK & C2 ANALYSIS');

            try {
                var URL = Java.use("java.net.URL");
                URL.$init.overload('java.lang.String').implementation = function(url) {
                    if (url && !analyzedItems.urls.has(url)) {
                        logMessage('info', 'network', 'URL accessed: ' + url);
                        analyzedItems.urls.add(url);
                    }
                    return this.$init(url);
                };

                var HttpURLConnection = Java.use("java.net.HttpURLConnection");
                HttpURLConnection.setRequestProperty.implementation = function(key, value) {
                    if (key && value) {
                        if (key.toLowerCase().indexOf("user-agent") !== -1) {
                            logMessage('info', 'network', 'User-Agent: ' + value);
                        }
                        logMessage('debug', 'network', 'Header: ' + key + ': ' + value);
                    }
                    return this.setRequestProperty(key, value);
                };
                
                HttpURLConnection.getInputStream.implementation = function() {
                    logMessage('debug', 'network', 'Connection opened: ' + this.getURL().toString());
                    return this.getInputStream();
                };
                
                HttpURLConnection.getOutputStream.implementation = function() {
                    logMessage('debug', 'network', 'Sending data to: ' + this.getURL().toString());
                    return this.getOutputStream();
                };
            } catch (e) {
                logMessage('error', 'network', 'Error hooking HTTP: ' + e.message);
            }

            try {
                var OkHttpClient = Java.use("okhttp3.OkHttpClient");
                logMessage('info', 'network', 'OkHttp3 detected');
                
                try {
                    var Request = Java.use("okhttp3.Request");
                    var Request$Builder = Java.use("okhttp3.Request$Builder");
                    
                    Request$Builder.url.overload('java.lang.String').implementation = function(url) {
                        if (url && !analyzedItems.urls.has(url)) {
                            logMessage('info', 'network', 'OkHttp URL: ' + url);
                            analyzedItems.urls.add(url);
                        }
                        return this.url(url);
                    };
                    
                    Request$Builder.build.implementation = function() {
                        var request = this.build();
                        var method = request.method().toString();
                        var url = request.url().toString();
                        logMessage('info', 'network', `OkHttp ${method} request to ${url}`);
                        return request;
                    };

                    try {
                        var RealCall = Java.use("okhttp3.internal.connection.RealCall");
                        RealCall.execute.implementation = function() {
                            var request = this.request();
                            var url = request.url().toString();
                            var method = request.method();
                            logMessage('info', 'network', `OkHttp executing ${method} to ${url}`);
                            return this.execute();
                        };
                    } catch (e) {
                        logMessage('debug', 'network', 'Could not hook RealCall: ' + e.message);
                    }
                } catch (e) {
                    logMessage('error', 'network', 'Error hooking OkHttp components: ' + e.message);
                }
            } catch (e) {
                logMessage('info', 'network', 'OkHttp3 not found');
            }

            try {
                var Volley = Java.use("com.android.volley.toolbox.Volley");
                logMessage('info', 'network', 'Volley detected');
                
                var StringRequest = Java.use("com.android.volley.toolbox.StringRequest");
                StringRequest.$init.overload('int', 'java.lang.String', 'com.android.volley.Response$Listener', 'com.android.volley.Response$ErrorListener').implementation = function(method, url, listener, errorListener) {
                    if (url && !analyzedItems.urls.has(url)) {
                        logMessage('info', 'network', 'Volley request to: ' + url);
                        analyzedItems.urls.add(url);
                    }
                    return this.$init(method, url, listener, errorListener);
                };
            } catch (e) {
                logMessage('debug', 'network', 'Volley not found');
            }

            try {
                var TrustManager = Java.use('javax.net.ssl.X509TrustManager');
                var SSLContext = Java.use('javax.net.ssl.SSLContext');

                var TrustManagerImpl = Java.registerClass({
                    name: 'com.frida.TrustManagerImpl',
                    implements: [TrustManager],
                    methods: {
                        checkClientTrusted: function(chain, authType) {},
                        checkServerTrusted: function(chain, authType) {},
                        getAcceptedIssuers: function() { return []; }
                    }
                });
                
                var TrustManagers = [TrustManagerImpl.$new()];
                var SSLContext_init = SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom');
                
                SSLContext_init.implementation = function(keyManager, trustManager, secureRandom) {
                    logMessage('info', 'bypass', 'Bypassing SSL certificate checks');
                    SSLContext_init.call(this, keyManager, TrustManagers, secureRandom);
                };
                
                logMessage('success', 'bypass', 'SSL certificate pinning bypass installed');
            } catch (e) {
                logMessage('error', 'bypass', 'Error bypassing certificate pinning: ' + e.message);
            }
        });
    }

    function monitorCryptography() {
        Java.perform(function() {
            logMessage('info', 'crypto', '🔐 CRYPTOGRAPHY ANALYSIS');

            try {
                var Cipher = Java.use("javax.crypto.Cipher");
                Cipher.getInstance.overload('java.lang.String').implementation = function(transformation) {
                    if (!analyzedItems.cryptoAlgorithms.has(transformation)) {
                        logMessage('info', 'crypto', 'Cipher algorithm: ' + transformation);
                        analyzedItems.cryptoAlgorithms.add(transformation);
                    }
                    return this.getInstance(transformation);
                };

                Cipher.doFinal.overload('[B').implementation = function(input) {
                    const mode = this.getOpmode();
                    const algorithm = this.getAlgorithm();
                    const modeStr = mode === 1 ? "ENCRYPT" : "DECRYPT";
                    
                    logMessage('debug', 'crypto', `${modeStr} operation with ${algorithm}`);
                    if (input && input.length < 1000) { // Only log reasonable size data
                        logMessage('debug', 'crypto', `${modeStr} input (${input.length} bytes): ${bytesToHex(input)}`);
                    }
                    
                    var result = this.doFinal(input);
                    
                    if (result && result.length < 1000) {
                        logMessage('debug', 'crypto', `${modeStr} output (${result.length} bytes): ${bytesToHex(result)}`);
                    }
                    
                    return result;
                };

                var SecretKeySpec = Java.use("javax.crypto.spec.SecretKeySpec");
                SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(key, algorithm) {
                    logMessage('info', 'crypto', 'Key algorithm: ' + algorithm);
                    logMessage('info', 'crypto', 'Key length: ' + key.length + ' bytes');
                    logMessage('info', 'crypto', 'Key material: ' + bytesToHex(key));
                    return this.$init(key, algorithm);
                };

                var IvParameterSpec = Java.use("javax.crypto.spec.IvParameterSpec");
                IvParameterSpec.$init.overload('[B').implementation = function(iv) {
                    logMessage('info', 'crypto', 'IV length: ' + iv.length + ' bytes');
                    logMessage('info', 'crypto', 'IV value: ' + bytesToHex(iv));
                    return this.$init(iv);
                };

                var MessageDigest = Java.use("java.security.MessageDigest");
                MessageDigest.getInstance.overload('java.lang.String').implementation = function(algorithm) {
                    if (!analyzedItems.cryptoAlgorithms.has(`MessageDigest:${algorithm}`)) {
                        logMessage('info', 'crypto', 'Hash algorithm: ' + algorithm);
                        analyzedItems.cryptoAlgorithms.add(`MessageDigest:${algorithm}`);
                    }
                    return this.getInstance(algorithm);
                };
                
                MessageDigest.digest.overload().implementation = function() {
                    const algorithm = this.getAlgorithm();
                    logMessage('debug', 'crypto', `Hashing with ${algorithm}`);
                    var result = this.digest();
                    logMessage('debug', 'crypto', `Hash result: ${bytesToHex(result)}`);
                    return result;
                };
            } catch (e) {
                logMessage('error', 'crypto', 'Error hooking crypto: ' + e.message);
            }
        });
    }
    
    function monitorDatabases() {
        Java.perform(function() {
            logMessage('info', 'database', '🗄️ DATABASE OPERATIONS');

            try {
                var SQLiteDatabase = Java.use("android.database.sqlite.SQLiteDatabase");

                SQLiteDatabase.openOrCreateDatabase.overload('java.io.File', 'android.database.sqlite.SQLiteDatabase$CursorFactory').implementation = function(file, factory) {
                    logMessage('info', 'database', 'Opening database: ' + file.getAbsolutePath());
                    return this.openOrCreateDatabase(file, factory);
                };

                SQLiteDatabase.execSQL.overload('java.lang.String').implementation = function(sql) {
                    if (!analyzedItems.databaseOperations.has(sql)) {
                        logMessage('info', 'database', 'SQL query: ' + sql);
                        analyzedItems.databaseOperations.add(sql);
                    }
                    return this.execSQL(sql);
                };
                
                SQLiteDatabase.execSQL.overload('java.lang.String', '[Ljava.lang.Object;').implementation = function(sql, bindArgs) {
                    if (!analyzedItems.databaseOperations.has(sql)) {
                        let argsStr = '';
                        if (bindArgs && bindArgs.length > 0) {
                            argsStr = ' with args: ' + JSON.stringify(bindArgs);
                        }
                        logMessage('info', 'database', 'SQL query: ' + sql + argsStr);
                        analyzedItems.databaseOperations.add(sql);
                    }
                    return this.execSQL(sql, bindArgs);
                };

                SQLiteDatabase.query.overload('java.lang.String', '[Ljava.lang.String;', 'java.lang.String', '[Ljava.lang.String;', 'java.lang.String', 'java.lang.String', 'java.lang.String', 'java.lang.String').implementation = function(table, columns, selection, selectionArgs, groupBy, having, orderBy, limit) {
                    const query = `SELECT ${columns ? columns.join(', ') : '*'} FROM ${table}${selection ? ' WHERE ' + selection : ''}`;
                    if (!analyzedItems.databaseOperations.has(query)) {
                        logMessage('info', 'database', 'Query: ' + query);
                        analyzedItems.databaseOperations.add(query);
                    }
                    return this.query(table, columns, selection, selectionArgs, groupBy, having, orderBy, limit);
                };

                SQLiteDatabase.insert.overload('java.lang.String', 'java.lang.String', 'android.content.ContentValues').implementation = function(table, nullColumnHack, values) {
                    logMessage('info', 'database', 'Insert into table: ' + table);
                    return this.insert(table, nullColumnHack, values);
                };
            } catch (e) {
                logMessage('error', 'database', 'Error hooking SQLite: ' + e.message);
            }

            try {
                var RoomDatabase = Java.use("androidx.room.RoomDatabase");
                logMessage('info', 'database', 'Room Database framework detected');
            } catch (e) {
                logMessage('debug', 'database', 'Room Database not found');
            }

            try {
                var SharedPreferencesImpl = Java.use("android.app.SharedPreferencesImpl");
                
                SharedPreferencesImpl.getString.implementation = function(key, defValue) {
                    var value = this.getString(key, defValue);
                    logMessage('info', 'database', `SharedPreferences - Read '${key}': '${value}'`);
                    return value;
                };
                
                var Editor = Java.use("android.app.SharedPreferencesImpl$EditorImpl");
                
                Editor.putString.implementation = function(key, value) {
                    logMessage('info', 'database', `SharedPreferences - Write '${key}': '${value}'`);
                    return this.putString(key, value);
                };
            } catch (e) {
                logMessage('error', 'database', 'Error hooking SharedPreferences: ' + e.message);
            }
        });
    }
    
    function monitorWebView() {
        Java.perform(function() {
            logMessage('info', 'webview', '🌍 WEBVIEW ANALYSIS');
            
            try {
                var WebView = Java.use("android.webkit.WebView");

                WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
                    if (!analyzedItems.urls.has(url)) {
                        logMessage('info', 'webview', 'WebView loading URL: ' + url);
                        analyzedItems.urls.add(url);
                    }
                    return this.loadUrl(url);
                };

                WebView.addJavascriptInterface.implementation = function(obj, name) {
                    const objClass = obj.getClass().getName();
                    logMessage('info', 'webview', `JavaScript interface added: ${name} (${objClass})`);

                    try {
                        const methods = Java.use(objClass).class.getDeclaredMethods();
                        for (let i = 0; i < methods.length; i++) {
                            const method = methods[i];
                            const JavascriptInterface = Java.use("android.webkit.JavascriptInterface");
                            const annotations = method.getAnnotations();
                            
                            for (let j = 0; j < annotations.length; j++) {
                                if (annotations[j].toString().indexOf("JavascriptInterface") !== -1) {
                                    logMessage('info', 'webview', `Exposed method: ${method.getName()}`);
                                    break;
                                }
                            }
                        }
                    } catch (e) {
                        logMessage('error', 'webview', 'Error inspecting JS interface: ' + e.message);
                    }
                    
                    return this.addJavascriptInterface(obj, name);
                };

                WebView.evaluateJavascript.implementation = function(script, resultCallback) {
                    logMessage('info', 'webview', 'JavaScript executed: ' + script);
                    return this.evaluateJavascript(script, resultCallback);
                };

                var CookieManager = Java.use("android.webkit.CookieManager");
                CookieManager.setCookie.implementation = function(url, value) {
                    logMessage('info', 'webview', `Cookie set for ${url}: ${value}`);
                    return this.setCookie(url, value);
                };
            } catch (e) {
                logMessage('error', 'webview', 'Error hooking WebView: ' + e.message);
            }
        });
    }
    
    function monitorReflection() {
        Java.perform(function() {
            logMessage('info', 'reflection', '🔄 REFLECTION & DYNAMIC CODE');

            try {
                var DexClassLoader = Java.use("dalvik.system.DexClassLoader");
                DexClassLoader.$init.implementation = function(dexPath, optimizedDirectory, librarySearchPath, parent) {
                    logMessage('info', 'reflection', 'DexClassLoader loading: ' + dexPath);
                    return this.$init(dexPath, optimizedDirectory, librarySearchPath, parent);
                };
                
                var PathClassLoader = Java.use("dalvik.system.PathClassLoader");
                PathClassLoader.$init.overload('java.lang.String', 'java.lang.ClassLoader').implementation = function(dexPath, parent) {
                    logMessage('info', 'reflection', 'PathClassLoader loading: ' + dexPath);
                    return this.$init(dexPath, parent);
                };
            } catch (e) {
                logMessage('error', 'reflection', 'Error hooking class loaders: ' + e.message);
            }

            try {
                var Method = Java.use("java.lang.reflect.Method");
                Method.invoke.implementation = function(obj, args) {
                    try {
                        const methodName = this.getName();
                        const className = this.getDeclaringClass().getName();
                        
                        if (!analyzedItems.reflectiveAccess.has(`${className}.${methodName}`)) {
                            logMessage('info', 'reflection', `Reflection: ${className}.${methodName}()`);
                            analyzedItems.reflectiveAccess.add(`${className}.${methodName}`);
                        }
                    } catch (e) {
                        logMessage('error', 'reflection', 'Error logging reflection: ' + e);
                    }
                    
                    return this.invoke(obj, args);
                };
            } catch (e) {
                logMessage('error', 'reflection', 'Error hooking reflection: ' + e.message);
            }

            try {
                var Class = Java.use("java.lang.Class");
                Class.forName.overload('java.lang.String').implementation = function(className) {
                    if (!analyzedItems.reflectiveAccess.has(`Class.forName:${className}`)) {
                        logMessage('info', 'reflection', 'Class.forName: ' + className);
                        analyzedItems.reflectiveAccess.add(`Class.forName:${className}`);
                    }
                    return this.forName(className);
                };
            } catch (e) {
                logMessage('error', 'reflection', 'Error hooking Class.forName: ' + e.message);
            }
        });
    }
    
    function monitorFileSystem() {
        Java.perform(function() {
            logMessage('info', 'filesystem', '💾 FILESYSTEM OPERATIONS');
            
            try {
                var context = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
                var filesDir = context.getFilesDir().getAbsolutePath();
                var cacheDir = context.getCacheDir().getAbsolutePath();
                
                logMessage('info', 'filesystem', 'Files directory: ' + filesDir);
                logMessage('info', 'filesystem', 'Cache directory: ' + cacheDir);

                var File = Java.use("java.io.File");
                var themainxDir = new File(filesDir + "/.themainx");
                if (themainxDir.exists()) {
                    logMessage('info', 'filesystem', '.themainx directory found: ' + themainxDir.getAbsolutePath());

                    try {
                        var files = themainxDir.listFiles();
                        if (files) {
                            for (var i = 0; i < files.length; i++) {
                                logMessage('info', 'filesystem', `- ${files[i].getName()} (${files[i].length()} bytes)`);
                            }
                        }
                    } catch (e) {
                        logMessage('error', 'filesystem', 'Error listing .themainx directory: ' + e.message);
                    }
                }

                File.$init.overload('java.lang.String').implementation = function(path) {
                    if (path.indexOf(filesDir) !== -1 || path.indexOf('/data/data') !== -1) {
                        if (!analyzedItems.fileOperations.has(path)) {
                            logMessage('info', 'filesystem', 'File accessed: ' + path);
                            analyzedItems.fileOperations.add(path);
                        }
                    }
                    return this.$init(path);
                };

                var FileOutputStream = Java.use("java.io.FileOutputStream");
                FileOutputStream.$init.overload('java.io.File').implementation = function(file) {
                    const path = file.getAbsolutePath();
                    if (!analyzedItems.fileOperations.has(`write:${path}`)) {
                        logMessage('info', 'filesystem', 'File write: ' + path);
                        analyzedItems.fileOperations.add(`write:${path}`);
                    }
                    return this.$init(file);
                };

                var FileInputStream = Java.use("java.io.FileInputStream");
                FileInputStream.$init.overload('java.io.File').implementation = function(file) {
                    const path = file.getAbsolutePath();
                    if (!analyzedItems.fileOperations.has(`read:${path}`)) {
                        logMessage('info', 'filesystem', 'File read: ' + path);
                        analyzedItems.fileOperations.add(`read:${path}`);
                    }
                    return this.$init(file);
                };
            } catch (e) {
                logMessage('error', 'filesystem', 'Error monitoring filesystem: ' + e.message);
            }
        });
    }
    
    function analyzePermissions() {
        Java.perform(function() {
            logMessage('info', 'permission', '🛡️ PERMISSIONS ANALYSIS');
            
            try {
                var context = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
                var packageManager = context.getPackageManager();
                var packageName = context.getPackageName();

                var PackageManager = Java.use("android.content.pm.PackageManager");
                var GET_PERMISSIONS = PackageManager.GET_PERMISSIONS.value;
                var packageInfo = packageManager.getPackageInfo(packageName, GET_PERMISSIONS);
                
                var permissions = packageInfo.requestedPermissions.value;
                if (permissions) {

                    const dangerousPermissions = [
                        "android.permission.READ_CONTACTS",
                        "android.permission.WRITE_CONTACTS",
                        "android.permission.READ_CALL_LOG",
                        "android.permission.WRITE_CALL_LOG",
                        "android.permission.READ_CALENDAR",
                        "android.permission.WRITE_CALENDAR",
                        "android.permission.READ_SMS",
                        "android.permission.SEND_SMS",
                        "android.permission.RECEIVE_SMS",
                        "android.permission.RECORD_AUDIO",
                        "android.permission.CAMERA",
                        "android.permission.ACCESS_FINE_LOCATION",
                        "android.permission.ACCESS_COARSE_LOCATION",
                        "android.permission.ACCESS_BACKGROUND_LOCATION",
                        "android.permission.READ_EXTERNAL_STORAGE",
                        "android.permission.WRITE_EXTERNAL_STORAGE",
                        "android.permission.READ_PHONE_STATE",
                        "android.permission.READ_PHONE_NUMBERS"
                    ];
                    
                    for (var i = 0; i < permissions.length; i++) {
                        var perm = permissions[i];
                        const isDangerous = dangerousPermissions.includes(perm);
                        const icon = isDangerous ? '⚠️' : '🔓';
                        logMessage('info', 'permission', `${icon} ${perm}${isDangerous ? ' (dangerous)' : ''}`);
                    }
                } else {
                    logMessage('info', 'permission', 'No permissions requested');
                }

                var Activity = Java.use("android.app.Activity");
                Activity.requestPermissions.implementation = function(permissions, requestCode) {
                    logMessage('info', 'permission', 'Runtime permission request (code: ' + requestCode + '):');
                    for (var i = 0; i < permissions.length; i++) {
                        logMessage('info', 'permission', '- ' + permissions[i]);
                    }
                    return this.requestPermissions(permissions, requestCode);
                };
            } catch (e) {
                logMessage('error', 'permission', 'Error analyzing permissions: ' + e.message);
            }
        });
    }

    function analyzeAntiAnalysisFeatures() {
        Java.perform(function() {
            logMessage('info', 'anti-analysis', '👁️ ANTI-ANALYSIS FEATURES');

            try {
                var Debug = Java.use("android.os.Debug");
                Debug.isDebuggerConnected.implementation = function() {
                    logMessage('info', 'anti-analysis', 'Debugger detection attempted');
                    return false;
                };
            } catch (e) {
                logMessage('error', 'anti-analysis', 'Error hooking Debug: ' + e.message);
            }

            try {
                var Build = Java.use("android.os.Build");
                logMessage('info', 'anti-analysis', 'Device model: ' + Build.MODEL.value);
                logMessage('info', 'anti-analysis', 'Manufacturer: ' + Build.MANUFACTURER.value);
                logMessage('info', 'anti-analysis', 'Product: ' + Build.PRODUCT.value);
                logMessage('info', 'anti-analysis', 'Brand: ' + Build.BRAND.value);
            } catch (e) {
                logMessage('error', 'anti-analysis', 'Error getting device info: ' + e.message);
            }

            try {
                var Runtime = Java.use("java.lang.Runtime");
                var RuntimeInstance = Runtime.getRuntime();
                var Process = Java.use("java.lang.Process");
                
                Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
                    if (cmd.indexOf("su") !== -1 || cmd.indexOf("which") !== -1 && cmd.indexOf("su") !== -1) {
                        logMessage('info', 'anti-analysis', 'Root check detected: ' + cmd);
                    } else if (cmd.indexOf("getprop") !== -1) {
                        logMessage('info', 'anti-analysis', 'Property check: ' + cmd);
                    } else {
                        logMessage('debug', 'anti-analysis', 'Runtime.exec: ' + cmd);
                    }
                    return this.exec(cmd);
                };
                
                Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmdArray) {
                    if (cmdArray && cmdArray.length > 0) {
                        logMessage('debug', 'anti-analysis', 'Runtime.exec array: ' + cmdArray[0]);
                    }
                    return this.exec(cmdArray);
                };
            } catch (e) {
                logMessage('error', 'anti-analysis', 'Error hooking Runtime: ' + e.message);
            }

            try {
                var context = Java.use("android.app.ActivityThread").currentApplication().getApplicationContext();
                var pm = context.getPackageManager();
                var packageName = context.getPackageName();
                
                var ApplicationPackageManager = Java.use("android.app.ApplicationPackageManager");
                ApplicationPackageManager.getInstallerPackageName.implementation = function(pkg) {
                    var installer = this.getInstallerPackageName(pkg);
                    logMessage('info', 'anti-analysis', 'Installer check: ' + pkg + ' installed by ' + installer);
                    return installer;
                };
            } catch (e) {
                logMessage('error', 'anti-analysis', 'Error hooking installer check: ' + e.message);
            }
        });
    }
    
    function generateSummaryReport() {
        setTimeout(function() {
            logMessage('info', 'summary', '📊 ANALYSIS SUMMARY');

            logMessage('info', 'summary', `Unique URLs detected: ${analyzedItems.urls.size}`);
            if (analyzedItems.urls.size > 0) {
                logMessage('info', 'summary', 'Top domains:');
                const domains = new Map();
                analyzedItems.urls.forEach(url => {
                    try {
                        const domain = url.split('/')[2];
                        if (domain) {
                            domains.set(domain, (domains.get(domain) || 0) + 1);
                        }
                    } catch (e) {}
                });

                const sortedDomains = [...domains.entries()].sort((a, b) => b[1] - a[1]);
                sortedDomains.slice(0, 5).forEach(([domain, count]) => {
                    logMessage('info', 'summary', `- ${domain}: ${count} requests`);
                });
            }

            logMessage('info', 'summary', `Cryptographic algorithms used: ${analyzedItems.cryptoAlgorithms.size}`);
            if (analyzedItems.cryptoAlgorithms.size > 0) {
                logMessage('info', 'summary', 'Algorithms:');
                analyzedItems.cryptoAlgorithms.forEach(algo => {
                    logMessage('info', 'summary', `- ${algo}`);
                });
            }

            logMessage('info', 'summary', `Database operations detected: ${analyzedItems.databaseOperations.size}`);

            logMessage('info', 'summary', `Filesystem operations detected: ${analyzedItems.fileOperations.size}`);

            logMessage('info', 'summary', `Reflection operations detected: ${analyzedItems.reflectiveAccess.size}`);
            
            logMessage('info', 'summary', '📝 FINAL NOTES');
            logMessage('info', 'summary', 'Analysis complete. Remember to check logs for detailed information.');
            logMessage('info', 'summary', 'Consider examining detected network endpoints and cryptographic operations.');
            
        }, 10000); // Wait 10 seconds for all analysis to complete
    }

    installBypassHooks();

    setTimeout(function() {
        logMessage('info', 'main', 'Starting comprehensive analysis');

        analyzePackageInfo();
        monitorNetworkActivity();
        monitorCryptography();
        monitorDatabases();
        monitorWebView();
        monitorReflection();
        monitorFileSystem();
        analyzePermissions();
        analyzeAntiAnalysisFeatures();

        generateSummaryReport();
        
    }, config.delayBeforeAnalysis);
})();
