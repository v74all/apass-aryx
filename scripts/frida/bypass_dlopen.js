
const CONFIG = {

    targetLibs: ["libxv1.so", "xv1"],

    javaClasses: {
        loader: "xnotice.themainx.handler.Loader",
    },

    logging: {
        enableDebug: true,
        showSuccess: true,
        showStackTraces: false
    }
};

const STATS = {
    nativeInterceptions: 0,
    javaInterceptions: 0,
    errors: 0
};

const Utils = {
    log: function(type, message) {
        const prefix = {
            info: "[*]",
            success: "[+]",
            error: "[-]",
            bypass: "[Bypass]",
            debug: "[Debug]"
        }[type] || "[*]";
        
        console.log(`${prefix} ${message}`);
    },
    
    isTargetLib: function(libname) {
        if (!libname) return false;
        
        return CONFIG.targetLibs.some(target => 
            libname.toLowerCase().indexOf(target.toLowerCase()) !== -1);
    },
    
    printStats: function() {
        Utils.log("info", "=== Bypass Statistics ===");
        Utils.log("info", `Native interceptions: ${STATS.nativeInterceptions}`);
        Utils.log("info", `Java interceptions: ${STATS.javaInterceptions}`);
        Utils.log("info", `Errors encountered: ${STATS.errors}`);
    }
};

const NativeHooks = {
    installDlopenHooks: function() {
        try {

            const dlopenPtr = Module.findExportByName(null, "dlopen");
            if (dlopenPtr) {
                Interceptor.attach(dlopenPtr, {
                    onEnter: function(args) {
                        this.libname = args[0].readCString();
                        if (Utils.isTargetLib(this.libname)) {
                            Utils.log("bypass", `dlopen intercepted: ${this.libname}`);
                            this.shouldReturn = true;
                            STATS.nativeInterceptions++;
                        }
                    },
                    onLeave: function(retval) {
                        if (this.shouldReturn) {
                            Utils.log("bypass", `Returning NULL for ${this.libname} dlopen`);
                            retval.replace(ptr(0));
                        }
                    }
                });
                Utils.log("success", "dlopen hook installed successfully");
                return true;
            }

            const androidDlopenPtr = Module.findExportByName(null, "android_dlopen_ext");
            if (androidDlopenPtr) {
                Interceptor.attach(androidDlopenPtr, {
                    onEnter: function(args) {
                        this.libname = args[0].readCString();
                        if (Utils.isTargetLib(this.libname)) {
                            Utils.log("bypass", `android_dlopen_ext intercepted: ${this.libname}`);
                            this.shouldReturn = true;
                            STATS.nativeInterceptions++;
                        }
                    },
                    onLeave: function(retval) {
                        if (this.shouldReturn) {
                            Utils.log("bypass", `Returning NULL for ${this.libname} android_dlopen_ext`);
                            retval.replace(ptr(0));
                        }
                    }
                });
                Utils.log("success", "android_dlopen_ext hook installed successfully");
                return true;
            }
            
            Utils.log("error", "Neither dlopen nor android_dlopen_ext found");
            return false;
        } catch (e) {
            STATS.errors++;
            Utils.log("error", `Error setting up dlopen hooks: ${e.message}`);
            if (CONFIG.logging.showStackTraces) {
                Utils.log("error", `Stack trace: ${e.stack}`);
            }
            return false;
        }
    },

};

const JavaHooks = {
    hookLoaderClass: function() {
        try {
            const LoaderClass = Java.use(CONFIG.javaClasses.loader);

            LoaderClass.attach.implementation = function(param) {
                Utils.log("bypass", "Loader.attach() called - providing dummy implementation");
                STATS.javaInterceptions++;
                return;
            };
            Utils.log("success", "Loader.attach() native method bypassed");

            LoaderClass.attachBaseContext.implementation = function(context) {
                Utils.log("bypass", "Loader.attachBaseContext() called - calling parent but skipping native calls");
                STATS.javaInterceptions++;

                const Application = Java.use("android.app.Application");
                Application.attachBaseContext.call(this, context);
                
                Utils.log("bypass", "Successfully bypassed native library loading in attachBaseContext");
                return;
            };
            Utils.log("success", "Loader.attachBaseContext() method bypassed with proper context handling");
            return true;
        } catch (e) {
            if (e.message.indexOf("ClassNotFoundException") !== -1) {
                Utils.log("info", `Loader class ${CONFIG.javaClasses.loader} not found, skipping`);
            } else {
                STATS.errors++;
                Utils.log("error", `Error hooking Loader class: ${e.message}`);
                if (CONFIG.logging.showStackTraces) {
                    Utils.log("error", `Stack trace: ${e.stack}`);
                }
            }
            return false;
        }
    },
    
    hookSystemLoad: function() {
        try {
            const System = Java.use("java.lang.System");
            System.load.overload('java.lang.String').implementation = function(filename) {
                if (Utils.isTargetLib(filename)) {
                    Utils.log("bypass", `System.load intercepted: ${filename}`);
                    STATS.javaInterceptions++;
                    return;
                }
                return this.load(filename);
            };
            Utils.log("success", "System.load hook installed");
            return true;
        } catch (e) {
            STATS.errors++;
            Utils.log("error", `Error hooking System.load: ${e.message}`);
            return false;
        }
    },
    
    hookSystemLoadLibrary: function() {
        try {
            const System = Java.use("java.lang.System");
            System.loadLibrary.overload('java.lang.String').implementation = function(lib) {
                if (Utils.isTargetLib(lib)) {
                    Utils.log("bypass", `System.loadLibrary intercepted: ${lib}`);
                    STATS.javaInterceptions++;
                    return;
                }
                return this.loadLibrary(lib);
            };
            Utils.log("success", "System.loadLibrary hook installed");
            return true;
        } catch (e) {
            STATS.errors++;
            Utils.log("error", `Error hooking System.loadLibrary: ${e.message}`);
            return false;
        }
    },
    
    hookRuntimeMethods: function() {
        try {
            const Runtime = Java.use("java.lang.Runtime");

            Runtime.load0.overload('java.lang.Class', 'java.lang.String').implementation = function(clazz, filename) {
                if (Utils.isTargetLib(filename)) {
                    Utils.log("bypass", `Runtime.load0 intercepted: ${filename}`);
                    STATS.javaInterceptions++;
                    return;
                }
                return this.load0(clazz, filename);
            };
            Utils.log("success", "Runtime.load0 hook installed");

            Runtime.loadLibrary0.overload('java.lang.Class', 'java.lang.String').implementation = function(clazz, lib) {
                if (Utils.isTargetLib(lib)) {
                    Utils.log("bypass", `Runtime.loadLibrary0 intercepted: ${lib}`);
                    STATS.javaInterceptions++;
                    return;
                }
                return this.loadLibrary0(clazz, lib);
            };
            Utils.log("success", "Runtime.loadLibrary0 hook installed");
            return true;
        } catch (e) {
            STATS.errors++;
            Utils.log("error", `Error hooking Runtime methods: ${e.message}`);
            return false;
        }
    },

    hookClassLoader: function() {
        try {
            const BaseDexClassLoader = Java.use("dalvik.system.BaseDexClassLoader");
            const DexFile = Java.use("dalvik.system.DexFile");

            BaseDexClassLoader.findLibrary.implementation = function(name) {
                if (Utils.isTargetLib(name)) {
                    Utils.log("bypass", `BaseDexClassLoader.findLibrary intercepted: ${name}`);
                    STATS.javaInterceptions++;
                    return null;
                }
                return this.findLibrary(name);
            };
            Utils.log("success", "BaseDexClassLoader.findLibrary hook installed");
            return true;
        } catch (e) {

            Utils.log("info", `ClassLoader hooking unavailable: ${e.message}`);
            return false;
        }
    }
};

function main() {
    Utils.log("info", "Starting enhanced bypass script...");

    NativeHooks.installDlopenHooks();

    Java.perform(function() {
        Utils.log("info", "Java.perform started");

        JavaHooks.hookLoaderClass();

        JavaHooks.hookSystemLoad();
        JavaHooks.hookSystemLoadLibrary();
        JavaHooks.hookRuntimeMethods();
        JavaHooks.hookClassLoader();

        setTimeout(Utils.printStats, 5000);
    });

    Interceptor.attach(Module.findExportByName(null, "dlsym") || ptr(0), {
        onEnter: function(args) {
            const handle = args[0];
            const symbol = args[1].readCString();
            
            try {

                const modules = Process.enumerateModules();
                for (const module of modules) {
                    if (module.base.equals(handle) && Utils.isTargetLib(module.name)) {
                        Utils.log("error", `WARNING: Target library ${module.name} was loaded despite bypass!`);
                        break;
                    }
                }
            } catch (e) {

            }
        }
    });
}

main();
