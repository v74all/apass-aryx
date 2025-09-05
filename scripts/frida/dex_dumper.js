


'use strict';

console.log('[*] Enhanced Dex Dumper loaded');

const CONFIG = {
  scanDelayMs: 3000,           // Delay before scanning starts
  maxDexSizeMB: 512,           // Maximum DEX file size to consider valid
  minDexSizeBytes: 0x70,       // Minimum DEX file size to consider valid
  scanReadOnly: true,          // Scan read-only memory regions
  scanReadExec: true,          // Scan read-execute memory regions
  dumpClassLoaders: true,      // Attempt to dump from ClassLoaders
  outputSubdir: 'dex_dumps',   // Subdirectory name for output
  logLevel: 'info'             // Logging level: debug, info, warn, error
};

const state = {
  dumpedFiles: 0,
  dumpedStarts: {},
  startTime: null,
  packageName: null
};

const DEX_SIGNATURES = [
  [0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x35, 0x00], // dex\n035\0
  [0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x37, 0x00], // dex\n037\0
  [0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x38, 0x00], // dex\n038\0
  [0x64, 0x65, 0x78, 0x0a, 0x30, 0x33, 0x39, 0x00]  // dex\n039\0
];

const Log = {
  debug: function(msg) {
    if (CONFIG.logLevel === 'debug') console.log('[DEBUG] ' + msg);
  },
  info: function(msg) {
    if (['debug', 'info'].includes(CONFIG.logLevel)) console.log('[*] ' + msg);
  },
  warn: function(msg) {
    if (['debug', 'info', 'warn'].includes(CONFIG.logLevel)) console.log('[!] ' + msg);
  },
  error: function(msg) {
    console.log('[ERROR] ' + msg);
  }
};

function getPackageName() {
  return Java.perform(function() {
    try {
      var ActivityThread = Java.use('android.app.ActivityThread');
      var app = ActivityThread.currentApplication();
      if (!app) return null;
      var ctx = app.getApplicationContext();
      return ctx.getPackageName();
    } catch (e) {
      Log.debug('Failed to get package name: ' + e.message);
      return null;
    }
  });
}

function getExternalDir(subdir) {
  try {
    return Java.perform(function() {
      var ActivityThread = Java.use('android.app.ActivityThread');
      var app = ActivityThread.currentApplication();
      if (!app) return '/sdcard/Download';
      var ctx = app.getApplicationContext();
      var file = ctx.getExternalFilesDir(subdir);
      if (file) return file.getAbsolutePath();
      return '/sdcard/Download';
    });
  } catch (e) {
    Log.debug('Error getting external dir: ' + e.message);
    return '/sdcard/Download';
  }
}

function writeArrayToFile(path, jsBytes) {
  return Java.perform(function() {
    var FileOutputStream = Java.use('java.io.FileOutputStream');
    var fos = null;
    try {

      var JArray = Java.array('byte', jsBytes);

      var File = Java.use('java.io.File');
      var f = File.$new(path);
      var parent = f.getParentFile();
      if (parent && !parent.exists()) parent.mkdirs();

      fos = FileOutputStream.$new(path);
      fos.write(JArray);
      fos.flush();
      Log.info('Wrote ' + jsBytes.length + ' bytes to ' + path);
      state.dumpedFiles++;
      return true;
    } catch (e) {
      Log.error('Write failed: ' + e.message);
      return false;
    } finally {
      try { if (fos) fos.close(); } catch (_) {}
    }
  });
}

function readU32LE(ptr) {
  return ptr.readU32();
}

function validateDexHeader(header) {
  try {

    var fileSize = readU32LE(header.add(0x20));
    if (fileSize < CONFIG.minDexSizeBytes || fileSize > CONFIG.maxDexSizeMB * 1024 * 1024) {
      return null;
    }

    var headerSize = readU32LE(header.add(0x24));
    if (headerSize < 0x70) {
      return null;
    }

    var endianTag = readU32LE(header.add(0x28));
    if (endianTag !== 0x12345678 && endianTag !== 0x78563412) {
      return null;
    }
    
    return fileSize;
  } catch (e) {
    return null;
  }
}

function dumpDexAt(ptrBase, idx, version) {
  try {
    var header = ptrBase;
    var fileSize = validateDexHeader(header);
    if (!fileSize) {
      Log.debug('Invalid DEX header at ' + ptrBase);
      return false;
    }
    
    var buf = Memory.readByteArray(ptrBase, fileSize);

    var bytes = new Uint8Array(buf);
    var jsBytes = Array.prototype.slice.call(bytes);

    Java.perform(function() {
      var outDir = getExternalDir(CONFIG.outputSubdir);
      var ts = Date.now();
      var packageSuffix = state.packageName ? '_' + state.packageName : '';
      var versionStr = version !== undefined ? '_v' + version : '';
      var outPath = outDir + '/memdex_' + ts + '_' + idx + versionStr + packageSuffix + '.dex';
      writeArrayToFile(outPath, jsBytes);
    });
    return true;
  } catch (e) {
    Log.error('Dump failed: ' + e.message);
    return false;
  }
}

function scanRange(range, idxStart) {
  var dumped = 0;

  DEX_SIGNATURES.forEach(function(signature, versionIdx) {

    var pattern = '';
    for (var i = 0; i < signature.length; i++) {
      pattern += signature[i].toString(16).padStart(2, '0') + ' ';
    }
    pattern = pattern.trim();

    var results = Memory.scanSync(range.base, range.size, pattern);

    results.forEach(function(m, i) {
      var start = m.address.toString();
      if (state.dumpedStarts[start]) return;
      state.dumpedStarts[start] = true;

      var version = signature[6] - 0x30; // ASCII to number
      version = version * 10 + (signature[7] - 0x30);
      
      if (dumpDexAt(m.address, idxStart + i, version)) dumped++;
    });
  });
  
  return dumped;
}

function scanAll() {
  Log.info('Scanning memory for in-memory DEX files...');

  var ranges = [];
  if (CONFIG.scanReadOnly) {
    ranges = ranges.concat(Process.enumerateRangesSync({ protection: 'r--' }));
  }
  if (CONFIG.scanReadExec) {
    ranges = ranges.concat(Process.enumerateRangesSync({ protection: 'r-x' }));
  }
  
  Log.info('Scanning ' + ranges.length + ' memory regions');
  var total = 0;
  var lastProgress = 0;
  
  for (var i = 0; i < ranges.length; i++) {
    try {
      total += scanRange(ranges[i], i * 1000);

      var progress = Math.floor((i / ranges.length) * 100);
      if (progress >= lastProgress + 10) {
        Log.info('Scan progress: ' + progress + '% (' + total + ' DEX files found)');
        lastProgress = progress;
      }
    } catch (e) {
      Log.debug('Error scanning range: ' + e.message);
    }
  }
  
  var endTime = Date.now();
  var duration = (endTime - state.startTime) / 1000;
  Log.info('Dex scan complete in ' + duration.toFixed(2) + 's; dumped: ' + total);
}

function inspectClassLoaders() {
  if (!CONFIG.dumpClassLoaders) return;
  
  Log.info('Inspecting ClassLoaders...');
  
  Java.perform(function() {
    try {
      var B = Java.use('dalvik.system.BaseDexClassLoader');
      var loaders = [];
      
      Java.enumerateClassLoaders({
        onMatch: function(cl) {
          try { 
            if (Java.cast(cl, B)) loaders.push(cl); 
          } catch (_) {}
        },
        onComplete: function() {}
      });
      
      Log.info('Found ' + loaders.length + ' ClassLoaders');
      
      loaders.forEach(function(cl, idx) {
        try {
          var bc = Java.cast(cl, B);
          var path = bc.getDexPath();
          Log.info('ClassLoader[' + idx + ']: ' + path);

        } catch (e) {
          Log.debug('Error inspecting ClassLoader: ' + e.message);
        }
      });
    } catch (e) { 
      Log.error('ClassLoader inspection failed: ' + e.message); 
    }
  });
}

function main() {
  state.startTime = Date.now();
  Log.info('Starting Enhanced DEX Dumper');

  state.packageName = getPackageName();
  if (state.packageName) {
    Log.info('Target package: ' + state.packageName);
  }

  try {
    inspectClassLoaders();
  } catch (e) {
    Log.error('Error in ClassLoader inspection: ' + e.message);
  }

  scanAll();
}

setTimeout(main, CONFIG.scanDelayMs);
