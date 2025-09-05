'use strict';



console.log('[+] APASS ARYX: Crypto/File bypass dumper initialized');

const CONFIG = {
  outSubdir: 'decrypted_dumps',
  maxCaptureBytes: 1024 * 1024 * 5, // 5MB per artifact for larger payloads
  captureCipherDoFinal: true,
  captureCipherInputStream: true,
  captureCipherOutputStream: true,  // Added support for output streams
  captureMessageDigest: true,       // Added support for hash functions
  mirrorSuspiciousWrites: true,
  trackFileDescriptors: true,       // Track file descriptors for native I/O
  suspiciousWriteExts: ['.dex', '.odex', '.vdex', '.so', '.jar', '.zip', '.apk', '.tmp', '.dat', '.bin'],
  logLevel: 'info',
  metadataCollection: true,         // Collect metadata about operations
  uniqueFilenameSalt: Date.now(),   // Ensure unique filenames across runs
};


const Log = {
  info: (m) => { 
    if (['debug','info'].includes(CONFIG.logLevel)) {
      console.log('[*] ' + m); 
      if (CONFIG.metadataCollection) {
        sendEvent({ type: 'log', level: 'info', message: m, timestamp: new Date().toISOString() });
      }
    }
  },
  debug: (m) => { 
    if (CONFIG.logLevel === 'debug') {
      console.log('[DEBUG] ' + m);
      if (CONFIG.metadataCollection) {
        sendEvent({ type: 'log', level: 'debug', message: m, timestamp: new Date().toISOString() });
      }
    }
  },
  warn: (m) => {
    console.log('[!] ' + m);
    sendEvent({ type: 'log', level: 'warning', message: m, timestamp: new Date().toISOString() });
  },
  error: (m) => {
    console.log('[ERROR] ' + m);
    sendEvent({ type: 'log', level: 'error', message: m, timestamp: new Date().toISOString() });
  },
  success: (m) => {
    console.log('[+] ' + m);
    sendEvent({ type: 'log', level: 'success', message: m, timestamp: new Date().toISOString() });
  }
};


function sendEvent(obj) {
  try { 

    if (!obj.timestamp) {
      obj.timestamp = new Date().toISOString();
    }
    send(JSON.stringify(obj)); 
  } catch (e) {
    console.log('[ERROR] Failed to send event: ' + e.message);
  }
}


function bytesToHex(bytes, limit = Number.MAX_SAFE_INTEGER) {
  const len = Math.min(bytes.length, limit);
  let hex = '';
  for (let i = 0; i < len; i++) {
    const b = bytes[i] & 0xff;
    hex += ('00' + b.toString(16)).slice(-2);
  }
  if (bytes.length > limit) {
    hex += '... (' + bytes.length + ' bytes total)';
  }
  return hex;
}


function createSimpleHash(input) {
  if (typeof input !== 'string') {
    input = String(input);
  }
  let hash = 0;
  for (let i = 0; i < input.length; i++) {
    const char = input.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32bit integer
  }
  return Math.abs(hash).toString(16);
}


function getExternalDir(subdir) {
  return Java.perform(function() {
    try {
      const ActivityThread = Java.use('android.app.ActivityThread');
      const app = ActivityThread.currentApplication();
      if (!app) {
        Log.debug('No current application, using fallback directory');
        return '/sdcard/Download/' + (subdir || '');
      }
      
      const ctx = app.getApplicationContext();
      const f = ctx.getExternalFilesDir(subdir);
      if (!f) {
        Log.debug('External files dir not available, using fallback');
        return '/sdcard/Download/' + (subdir || '');
      }
      
      const path = f.getAbsolutePath();
      Log.debug('Using external directory: ' + path);

      const File = Java.use('java.io.File');
      const dirFile = File.$new(path);
      if (!dirFile.exists()) {
        const created = dirFile.mkdirs();
        Log.debug('Created directory: ' + path + ' - ' + created);
      }
      
      return path;
    } catch (e) {
      Log.error('getExternalDir failed: ' + e.message + '\n' + e.stack);
      return '/sdcard/Download/' + (subdir || '');
    }
  });
}


function generateUniqueFilename(prefix, extension, metadata = {}) {
  const timestamp = Date.now();
  const random = Math.floor(Math.random() * 10000);
  let metadataStr = '';
  
  if (metadata.algorithm) {
    metadataStr += '_' + metadata.algorithm.replace(/\W+/g, '_');
  }
  if (metadata.operation) {
    metadataStr += '_' + metadata.operation;
  }
  if (metadata.size) {
    metadataStr += '_' + metadata.size + 'b';
  }
  
  return `${prefix}_${timestamp}_${random}${metadataStr}.${extension}`;
}


function writeBytesToFile(path, jsBytes, metadata = {}) {
  return Java.perform(function() {
    const FileOutputStream = Java.use('java.io.FileOutputStream');
    const File = Java.use('java.io.File');
    const BufferedOutputStream = Java.use('java.io.BufferedOutputStream');
    let fos = null;
    let bos = null;
    
    try {
      const f = File.$new(path);
      const parent = f.getParentFile();
      if (parent && !parent.exists()) {
        const created = parent.mkdirs();
        if (!created) {
          Log.warn('Failed to create parent directory for: ' + path);
        }
      }

      const JArray = Java.array('byte', jsBytes);

      fos = FileOutputStream.$new(path);
      bos = BufferedOutputStream.$new(fos);
      bos.write(JArray);
      bos.flush();

      sendEvent({ 
        type: 'file_written', 
        payload: { 
          path: path, 
          size: jsBytes.length,
          timestamp: new Date().toISOString(),
          metadata: metadata
        } 
      });
      
      return true;
    } catch (e) {
      Log.error('writeBytesToFile failed: ' + e.message + '\n' + e.stack);
      return false;
    } finally {
      try { 
        if (bos) bos.close(); 
        else if (fos) fos.close(); 
      } catch (e) {
        Log.debug('Error closing output stream: ' + e.message);
      }
    }
  });
}


function copyFileTo(path, outDir, metadata = {}) {
  return Java.perform(function() {

    try {
      const File = Java.use('java.io.File');
      const Files = Java.use('java.nio.file.Files');
      const Paths = Java.use('java.nio.file.Paths');
      const StandardCopyOption = Java.use('java.nio.file.StandardCopyOption');

      const src = Paths.get(path, Java.array('java.lang.String', []));

      const originalName = new File(path).getName();
      const fileHash = createSimpleHash(path + CONFIG.uniqueFilenameSalt);
      const outPath = outDir + '/' + fileHash + '_' + originalName;

      const dst = Paths.get(outPath, Java.array('java.lang.String', []));

      const dstFile = File.$new(outPath);
      const parent = dstFile.getParentFile();
      if (parent && !parent.exists()) {
        parent.mkdirs();
      }

      const copyOptions = Java.array('java.nio.file.CopyOption', [StandardCopyOption.REPLACE_EXISTING]);
      Files.copy(src, dst, copyOptions);

      const fileSize = Files.size(dst);
      
      Log.success('Successfully copied file: ' + path + ' to ' + outPath + ' (' + fileSize + ' bytes)');

      sendEvent({ 
        type: 'file_copied', 
        payload: { 
          source: path,
          destination: outPath,
          size: fileSize,
          timestamp: new Date().toISOString(),
          metadata: metadata
        }
      });
      
      return outPath;
    } catch (e) {
      Log.debug('NIO copy failed, falling back to stream method: ' + e.message);

      let input = null;
      let baos = null;
      
      try {
        const File = Java.use('java.io.File');
        const FileInputStream = Java.use('java.io.FileInputStream');
        const BufferedInputStream = Java.use('java.io.BufferedInputStream');
        const ByteArrayOutputStream = Java.use('java.io.ByteArrayOutputStream');

        input = FileInputStream.$new(path);
        const bis = BufferedInputStream.$new(input);

        baos = ByteArrayOutputStream.$new();

        const bufferSize = 32768; // 32KB buffer for better performance
        const buffer = Java.array('byte', new Array(bufferSize).fill(0));
        let read = 0;
        let totalRead = 0;

        while ((read = bis.read(buffer)) > 0) {
          baos.write(buffer, 0, read);
          totalRead += read;

          if (totalRead % (1024 * 1024) === 0) { // Every 1MB
            Log.debug('Copied ' + (totalRead / (1024 * 1024)) + ' MB so far');
          }
        }

        const bytes = baos.toByteArray();
        const jsBytes = Array.prototype.slice.call(new Uint8Array(bytes));

        const originalName = path.split('/').pop();
        const fileHash = createSimpleHash(path + CONFIG.uniqueFilenameSalt);
        const outPath = outDir + '/' + fileHash + '_' + originalName;

        if (writeBytesToFile(outPath, jsBytes, { 
          source: path, 
          operation: 'file_copy',
          size: jsBytes.length,
          ...metadata
        })) {
          Log.success('Successfully copied file using streams: ' + path + ' to ' + outPath + ' (' + jsBytes.length + ' bytes)');
          return outPath;
        } else {
          Log.error('Failed to write copied file: ' + outPath);
          return null;
        }
      } catch (e2) {
        Log.error('copyFileTo failed completely: ' + e2.message + '\n' + e2.stack);
        return null;
      } finally {
        try { if (input) input.close(); } catch (e) {  }
        try { if (baos) baos.close(); } catch (e) {  }
      }
    }
  });
}

const fileHandleMap = new Map();


function hookFileWrites(outDir) {
  Java.perform(function() {
    try {

      hookFileOutputStream(outDir);

      hookNioFiles(outDir);

      hookRandomAccessFile(outDir);
      
      Log.info('File write hooks installed successfully');
    } catch (e) {
      Log.error('hookFileWrites setup failed: ' + e.message + '\n' + e.stack);
    }
  });
}


function hookFileOutputStream(outDir) {
  try {
    const FileOutputStream = Java.use('java.io.FileOutputStream');
    const File = Java.use('java.io.File');


    FileOutputStream.$init.overload('java.io.File').implementation = function(file) {
      const path = file.getAbsolutePath();
      fileHandleMap.set(this, { 
        path: path, 
        type: 'FileOutputStream',
        created: new Date().toISOString()
      });
      Log.debug('FileOutputStream created for: ' + path);
      return this.$init(file);
    };

    FileOutputStream.$init.overload('java.lang.String').implementation = function(path) {
      fileHandleMap.set(this, { 
        path: path, 
        type: 'FileOutputStream',
        created: new Date().toISOString()
      });
      Log.debug('FileOutputStream created for: ' + path);
      return this.$init(path);
    };

    FileOutputStream.$init.overload('java.lang.String', 'boolean').implementation = function(path, append) {
      fileHandleMap.set(this, { 
        path: path, 
        type: 'FileOutputStream',
        append: append,
        created: new Date().toISOString()
      });
      Log.debug('FileOutputStream created for: ' + path + ' (append: ' + append + ')');
      return this.$init(path, append);
    };

    FileOutputStream.$init.overload('java.io.File', 'boolean').implementation = function(file, append) {
      const path = file.getAbsolutePath();
      fileHandleMap.set(this, { 
        path: path, 
        type: 'FileOutputStream',
        append: append,
        created: new Date().toISOString()
      });
      Log.debug('FileOutputStream created for: ' + path + ' (append: ' + append + ')');
      return this.$init(file, append);
    };


    FileOutputStream.write.overload('[B').implementation = function(buffer) {
      const info = fileHandleMap.get(this);
      
      if (info && info.path && CONFIG.mirrorSuspiciousWrites) {
        const path = info.path;
        const lower = path.toLowerCase();
        
        if (CONFIG.suspiciousWriteExts.some(ext => lower.endsWith(ext))) {
          try {
            const len = buffer.length;
            const cap = Math.min(len, CONFIG.maxCaptureBytes);
            const jsBytes = Array.prototype.slice.call(buffer).slice(0, cap);

            const fileName = generateUniqueFilename(
              'mirror', 
              path.split('.').pop() || 'bin',
              { operation: 'write_mirror', source: path }
            );
            const outPath = outDir + '/' + fileName;
            
            if (writeBytesToFile(outPath, jsBytes, { 
              source: path, 
              operation: 'write_mirror',
              append: info.append || false,
              size: jsBytes.length
            })) {
              Log.success('Mirrored suspicious write to ' + outPath + ' from ' + path);
              sendEvent({ 
                type: 'dump_saved', 
                payload: { 
                  path: outPath, 
                  kind: 'write_mirror', 
                  src: path, 
                  size: jsBytes.length,
                  timestamp: new Date().toISOString()
                } 
              });
            }
          } catch (e) { 
            Log.debug('Mirror write failed: ' + e.message); 
          }
        }
      }
      
      return this.write(buffer);
    };

    FileOutputStream.write.overload('[B', 'int', 'int').implementation = function(buffer, offset, length) {
      const info = fileHandleMap.get(this);
      
      if (info && info.path && CONFIG.mirrorSuspiciousWrites) {
        const path = info.path;
        const lower = path.toLowerCase();
        
        if (CONFIG.suspiciousWriteExts.some(ext => lower.endsWith(ext))) {
          try {
            const cap = Math.min(length, CONFIG.maxCaptureBytes);
            const jsBytes = Array.prototype.slice.call(buffer, offset, offset + cap);

            const fileName = generateUniqueFilename(
              'mirror_partial', 
              path.split('.').pop() || 'bin',
              { operation: 'partial_write_mirror', source: path }
            );
            const outPath = outDir + '/' + fileName;
            
            if (writeBytesToFile(outPath, jsBytes, { 
              source: path, 
              operation: 'partial_write_mirror',
              offset: offset,
              length: length,
              captured: cap,
              size: jsBytes.length
            })) {
              Log.success('Mirrored partial write to ' + outPath + ' from ' + path);
              sendEvent({ 
                type: 'dump_saved', 
                payload: { 
                  path: outPath, 
                  kind: 'partial_write_mirror', 
                  src: path, 
                  offset: offset,
                  length: length,
                  size: jsBytes.length,
                  timestamp: new Date().toISOString()
                } 
              });
            }
          } catch (e) { 
            Log.debug('Mirror partial write failed: ' + e.message); 
          }
        }
      }
      
      return this.write(buffer, offset, length);
    };
    
    Log.debug('FileOutputStream hooks installed successfully');
  } catch (e) {
    Log.error('hookFileOutputStream failed: ' + e.message);
  }
}


function hookCrypto() {
  Java.perform(function() {
    try {

      hookCipherOperations();

      if (CONFIG.captureMessageDigest) {
        hookMessageDigest();
      }

      hookMacOperations();

      hookKeyManagement();
      
      Log.info('Crypto hooks installed successfully');
    } catch (e) {
      Log.error('hookCrypto failed: ' + e.message + '\n' + e.stack);
    }
  });
}


function hookCipherOperations() {
  try {
    const Cipher = Java.use('javax.crypto.Cipher');
    const SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    const IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');

    const cipherInfoMap = new Map();

    Cipher.init.overload('int', 'java.security.Key', 'java.security.spec.AlgorithmParameterSpec').implementation = function(mode, key, params) {
      try {
        const alg = this.getAlgorithm();
        const modeStr = ['ENCRYPT_MODE', 'DECRYPT_MODE', 'WRAP_MODE', 'UNWRAP_MODE'][mode - 1] || 'UNKNOWN';

        cipherInfoMap.set(this, {
          algorithm: alg,
          mode: mode,
          modeStr: modeStr,
          keyClass: key.getClass().getName(),
          keyAlgorithm: key.getAlgorithm(),
          paramsClass: params ? params.getClass().getName() : null,
          timestamp: new Date().toISOString()
        });
        
        Log.info(`Cipher init: ${alg} (${modeStr}), Key: ${key.getAlgorithm()}`);

        if (params && params.$className === 'javax.crypto.spec.IvParameterSpec') {
          try {
            const iv = params.getIV();
            const ivHex = bytesToHex(iv, 32);
            Log.info(`IV detected: ${ivHex} (${iv.length} bytes)`);

            const info = cipherInfoMap.get(this);
            if (info) {
              info.ivHex = ivHex;
              info.ivLength = iv.length;
              cipherInfoMap.set(this, info);
            }

            sendEvent({
              type: 'crypto_params',
              payload: {
                type: 'iv',
                algorithm: alg,
                mode: modeStr,
                value: ivHex,
                length: iv.length,
                timestamp: new Date().toISOString()
              }
            });
          } catch (e) {
            Log.debug('Failed to extract IV: ' + e.message);
          }
        }
      } catch (e) {
        Log.debug('Error tracking cipher init: ' + e.message);
      }
      
      return this.init(mode, key, params);
    };

    SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(key, alg) {
      try {
        const keyHex = bytesToHex(key, 32);
        Log.info(`SecretKeySpec: algorithm=${alg}, key=${keyHex}... (${key.length} bytes)`);

        sendEvent({
          type: 'crypto_params',
          payload: {
            type: 'key',
            algorithm: alg,
            value: keyHex,
            length: key.length,
            timestamp: new Date().toISOString()
          }
        });
      } catch (e) {
        Log.debug('Failed to log key spec: ' + e.message);
      }
      
      return this.$init(key, alg);
    };

    IvParameterSpec.$init.overload('[B').implementation = function(iv) {
      try {
        const ivHex = bytesToHex(iv, 32);
        Log.info(`IvParameterSpec: iv=${ivHex}... (${iv.length} bytes)`);
      } catch (e) {
        Log.debug('Failed to log IV spec: ' + e.message);
      }
      
      return this.$init(iv);
    };

    if (CONFIG.captureCipherDoFinal) {

      Cipher.doFinal.overload('[B').implementation = function(input) {
        const info = cipherInfoMap.get(this) || {
          algorithm: this.getAlgorithm(),
          mode: this.getOpmode(),
          modeStr: ['ENCRYPT_MODE', 'DECRYPT_MODE', 'WRAP_MODE', 'UNWRAP_MODE'][this.getOpmode() - 1] || 'UNKNOWN'
        };
        
        const out = this.doFinal(input);
        
        try {

          if (info.mode !== 1 && out && out.length > 0) { // not ENCRYPT_MODE
            const cap = Math.min(out.length, CONFIG.maxCaptureBytes);
            const jsBytes = Array.prototype.slice.call(out).slice(0, cap);

            const fileName = generateUniqueFilename(
              'cipher', 
              'bin',
              { 
                algorithm: info.algorithm || 'unknown',
                operation: info.modeStr || 'unknown',
                size: jsBytes.length
              }
            );
            const dir = getExternalDir(CONFIG.outSubdir);
            const outPath = dir + '/' + fileName;
            
            if (writeBytesToFile(outPath, jsBytes, {
              algorithm: info.algorithm,
              operation: info.modeStr,
              keyAlgorithm: info.keyAlgorithm,
              ivHex: info.ivHex,
              inputSize: input.length,
              outputSize: out.length
            })) {
              Log.success(`Captured ${info.modeStr} output from Cipher.doFinal -> ${outPath}`);
              sendEvent({ 
                type: 'dump_saved', 
                payload: { 
                  path: outPath, 
                  kind: 'cipher_output', 
                  algorithm: info.algorithm || 'unknown',
                  mode: info.modeStr || 'unknown',
                  size: jsBytes.length,
                  timestamp: new Date().toISOString()
                } 
              });
            }
          }
        } catch (e) { 
          Log.debug('Cipher dump failed: ' + e.message); 
        }
        
        return out;
      };

      Cipher.doFinal.overload('[B', 'int', 'int').implementation = function(input, offset, length) {
        const info = cipherInfoMap.get(this) || {
          algorithm: this.getAlgorithm(),
          mode: this.getOpmode(),
          modeStr: ['ENCRYPT_MODE', 'DECRYPT_MODE', 'WRAP_MODE', 'UNWRAP_MODE'][this.getOpmode() - 1] || 'UNKNOWN'
        };
        
        const out = this.doFinal(input, offset, length);
        
        try {

          if (info.mode !== 1 && out && out.length > 0) { // not ENCRYPT_MODE
            const cap = Math.min(out.length, CONFIG.maxCaptureBytes);
            const jsBytes = Array.prototype.slice.call(out).slice(0, cap);

            const fileName = generateUniqueFilename(
              'cipher_partial', 
              'bin',
              { 
                algorithm: info.algorithm || 'unknown',
                operation: info.modeStr || 'unknown',
                size: jsBytes.length
              }
            );
            const dir = getExternalDir(CONFIG.outSubdir);
            const outPath = dir + '/' + fileName;
            
            if (writeBytesToFile(outPath, jsBytes, {
              algorithm: info.algorithm,
              operation: info.modeStr,
              keyAlgorithm: info.keyAlgorithm,
              ivHex: info.ivHex,
              inputOffset: offset,
              inputLength: length,
              outputSize: out.length
            })) {
              Log.success(`Captured ${info.modeStr} partial output from Cipher.doFinal -> ${outPath}`);
              sendEvent({ 
                type: 'dump_saved', 
                payload: { 
                  path: outPath, 
                  kind: 'cipher_partial_output', 
                  algorithm: info.algorithm || 'unknown',
                  mode: info.modeStr || 'unknown',
                  inputOffset: offset,
                  inputLength: length,
                  size: jsBytes.length,
                  timestamp: new Date().toISOString()
                } 
              });
            }
          }
        } catch (e) { 
          Log.debug('Cipher partial dump failed: ' + e.message); 
        }
        
        return out;
      };
    }

    if (CONFIG.captureCipherInputStream) {
      try {
        const CipherInputStream = Java.use('javax.crypto.CipherInputStream');

        const streamCipherMap = new WeakMap();

        CipherInputStream.$init.overload('java.io.InputStream', 'javax.crypto.Cipher').implementation = function(inStream, cipher) {
          try {
            streamCipherMap.set(this, {
              cipher: cipher,
              algorithm: cipher.getAlgorithm(),
              mode: cipher.getOpmode(),
              modeStr: ['ENCRYPT_MODE', 'DECRYPT_MODE', 'WRAP_MODE', 'UNWRAP_MODE'][cipher.getOpmode() - 1] || 'UNKNOWN',
              created: new Date().toISOString()
            });
            
            Log.debug(`CipherInputStream created with ${cipher.getAlgorithm()} cipher`);
          } catch (e) {
            Log.debug('Error tracking CipherInputStream: ' + e.message);
          }
          
          return this.$init(inStream, cipher);
        };

        CipherInputStream.read.overload('[B').implementation = function(buffer) {
          const count = this.read(buffer);
          
          if (count > 0) {
            try {
              const info = streamCipherMap.get(this) || { algorithm: 'unknown', modeStr: 'unknown' };
              const jsBytes = Array.prototype.slice.call(buffer).slice(0, Math.min(count, CONFIG.maxCaptureBytes));

              const fileName = generateUniqueFilename(
                'cis', 
                'bin',
                { 
                  algorithm: info.algorithm || 'unknown',
                  operation: 'stream_read',
                  size: jsBytes.length
                }
              );
              const dir = getExternalDir(CONFIG.outSubdir);
              const outPath = dir + '/' + fileName;
              
              if (writeBytesToFile(outPath, jsBytes, {
                algorithm: info.algorithm,
                operation: 'cipher_input_stream',
                readSize: count
              })) {
                Log.success(`Captured CipherInputStream data (${info.algorithm}) -> ${outPath}`);
                sendEvent({ 
                  type: 'dump_saved', 
                  payload: { 
                    path: outPath, 
                    kind: 'cipher_stream', 
                    algorithm: info.algorithm || 'unknown',
                    size: jsBytes.length,
                    timestamp: new Date().toISOString()
                  } 
                });
              }
            } catch (e) { 
              Log.debug('CipherInputStream dump failed: ' + e.message); 
            }
          }
          
          return count;
        };

        CipherInputStream.read.overload('[B', 'int', 'int').implementation = function(buffer, offset, length) {
          const count = this.read(buffer, offset, length);
          
          if (count > 0) {
            try {
              const info = streamCipherMap.get(this) || { algorithm: 'unknown', modeStr: 'unknown' };
              const jsBytes = Array.prototype.slice.call(buffer, offset, offset + Math.min(count, CONFIG.maxCaptureBytes));

              const fileName = generateUniqueFilename(
                'cis_partial', 
                'bin',
                { 
                  algorithm: info.algorithm || 'unknown',
                  operation: 'stream_read_partial',
                  size: jsBytes.length
                }
              );
              const dir = getExternalDir(CONFIG.outSubdir);
              const outPath = dir + '/' + fileName;
              
              if (writeBytesToFile(outPath, jsBytes, {
                algorithm: info.algorithm,
                operation: 'cipher_input_stream_partial',
                readOffset: offset,
                readLength: length,
                actualRead: count
              })) {
                Log.success(`Captured CipherInputStream partial data (${info.algorithm}) -> ${outPath}`);
                sendEvent({ 
                  type: 'dump_saved', 
                  payload: { 
                    path: outPath, 
                    kind: 'cipher_stream_partial', 
                    algorithm: info.algorithm || 'unknown',
                    offset: offset,
                    length: length,
                    actualRead: count,
                    size: jsBytes.length,
                    timestamp: new Date().toISOString()
                  } 
                });
              }
            } catch (e) { 
              Log.debug('CipherInputStream partial dump failed: ' + e.message); 
            }
          }
          
          return count;
        };
      } catch (e) { 
        Log.debug('CipherInputStream hooks failed: ' + e.message); 
      }
    }

    if (CONFIG.captureCipherOutputStream) {
      try {
        const CipherOutputStream = Java.use('javax.crypto.CipherOutputStream');

        const outputStreamCipherMap = new WeakMap();

        CipherOutputStream.$init.overload('java.io.OutputStream', 'javax.crypto.Cipher').implementation = function(outStream, cipher) {
          try {
            outputStreamCipherMap.set(this, {
              cipher: cipher,
              algorithm: cipher.getAlgorithm(),
              mode: cipher.getOpmode(),
              modeStr: ['ENCRYPT_MODE', 'DECRYPT_MODE', 'WRAP_MODE', 'UNWRAP_MODE'][cipher.getOpmode() - 1] || 'UNKNOWN',
              created: new Date().toISOString()
            });
            
            Log.debug(`CipherOutputStream created with ${cipher.getAlgorithm()} cipher`);
          } catch (e) {
            Log.debug('Error tracking CipherOutputStream: ' + e.message);
          }
          
          return this.$init(outStream, cipher);
        };

        CipherOutputStream.write.overload('[B').implementation = function(buffer) {
          try {
            const info = outputStreamCipherMap.get(this) || { algorithm: 'unknown', modeStr: 'unknown' };

            if (info.mode === 1) { // ENCRYPT_MODE
              const cap = Math.min(buffer.length, CONFIG.maxCaptureBytes);
              const jsBytes = Array.prototype.slice.call(buffer).slice(0, cap);

              const fileName = generateUniqueFilename(
                'cos_input', 
                'bin',
                { 
                  algorithm: info.algorithm || 'unknown',
                  operation: 'stream_write_plaintext',
                  size: jsBytes.length
                }
              );
              const dir = getExternalDir(CONFIG.outSubdir);
              const outPath = dir + '/' + fileName;
              
              if (writeBytesToFile(outPath, jsBytes, {
                algorithm: info.algorithm,
                operation: 'cipher_output_stream_input',
                size: buffer.length
              })) {
                Log.success(`Captured CipherOutputStream plaintext input (${info.algorithm}) -> ${outPath}`);
                sendEvent({ 
                  type: 'dump_saved', 
                  payload: { 
                    path: outPath, 
                    kind: 'cipher_stream_input', 
                    algorithm: info.algorithm || 'unknown',
                    size: jsBytes.length,
                    timestamp: new Date().toISOString()
                  } 
                });
              }
            }
          } catch (e) { 
            Log.debug('CipherOutputStream dump failed: ' + e.message); 
          }
          
          return this.write(buffer);
        };

        CipherOutputStream.write.overload('[B', 'int', 'int').implementation = function(buffer, offset, length) {
          try {
            const info = outputStreamCipherMap.get(this) || { algorithm: 'unknown', modeStr: 'unknown' };

            if (info.mode === 1) { // ENCRYPT_MODE
              const cap = Math.min(length, CONFIG.maxCaptureBytes);
              const jsBytes = Array.prototype.slice.call(buffer, offset, offset + cap);

              const fileName = generateUniqueFilename(
                'cos_input_partial', 
                'bin',
                { 
                  algorithm: info.algorithm || 'unknown',
                  operation: 'stream_write_plaintext_partial',
                  size: jsBytes.length
                }
              );
              const dir = getExternalDir(CONFIG.outSubdir);
              const outPath = dir + '/' + fileName;
              
              if (writeBytesToFile(outPath, jsBytes, {
                algorithm: info.algorithm,
                operation: 'cipher_output_stream_input_partial',
                offset: offset,
                length: length
              })) {
                Log.success(`Captured CipherOutputStream partial plaintext input (${info.algorithm}) -> ${outPath}`);
                sendEvent({ 
                  type: 'dump_saved', 
                  payload: { 
                    path: outPath, 
                    kind: 'cipher_stream_input_partial', 
                    algorithm: info.algorithm || 'unknown',
                    offset: offset,
                    length: length,
                    size: jsBytes.length,
                    timestamp: new Date().toISOString()
                  } 
                });
              }
            }
          } catch (e) { 
            Log.debug('CipherOutputStream partial dump failed: ' + e.message); 
          }
          
          return this.write(buffer, offset, length);
        };
      } catch (e) { 
        Log.debug('CipherOutputStream hooks failed: ' + e.message); 
      }
    }
    
    Log.debug('Cipher hooks installed successfully');
  } catch (e) {
    Log.error('hookCipherOperations failed: ' + e.message);
  }
}


function hookClassLoaders() {
  Java.perform(function() {

    const classLoaderStats = {
      totalDexPaths: 0,
      uniqueDexPaths: new Set(),
      loaders: {}
    };

    try {
      const BaseDexClassLoader = Java.use('dalvik.system.BaseDexClassLoader');
      
      BaseDexClassLoader.findClass.implementation = function(name) {
        try {

          const pathList = this.pathList.value;
          if (pathList) {
            const dexElements = pathList.dexElements.value;
            if (dexElements && dexElements.length > 0) {
              for (let i = 0; i < dexElements.length; i++) {
                const element = dexElements[i];
                const dexFile = element.dexFile.value;
                if (dexFile) {
                  const dexPath = dexFile.toString();
                  if (dexPath && !classLoaderStats.uniqueDexPaths.has(dexPath)) {
                    classLoaderStats.uniqueDexPaths.add(dexPath);
                    classLoaderStats.totalDexPaths++;
                    
                    Log.info(`BaseDexClassLoader detected new DexFile: ${dexPath}`);

                    const match = dexPath.match(/location=([^,]+)/);
                    if (match && match[1]) {
                      const filePath = match[1].trim();
                      try {
                        const dir = getExternalDir(CONFIG.outSubdir);
                        const outPath = copyFileTo(filePath, dir, {
                          operation: 'basedexclassloader_copy',
                          className: name
                        });
                        
                        if (outPath) {
                          Log.success(`Copied BaseDexClassLoader dexPath to ${outPath}`);
                          sendEvent({ 
                            type: 'dump_saved', 
                            payload: { 
                              path: outPath, 
                              kind: 'basedex_path_copy', 
                              src: filePath,
                              className: name,
                              timestamp: new Date().toISOString()
                            } 
                          });
                        }
                      } catch (e) { 
                        Log.debug(`Copy BaseDexClassLoader dexPath failed: ${e.message}`); 
                      }
                    }
                  }
                }
              }
            }
          }
        } catch (e) {
          Log.debug(`Error examining BaseDexClassLoader: ${e.message}`);
        }
        
        return this.findClass(name);
      };
      
      Log.debug('BaseDexClassLoader hook installed successfully');
    } catch (e) { 
      Log.debug(`BaseDexClassLoader hook failed: ${e.message}`); 
    }

    try {
      const DexClassLoader = Java.use('dalvik.system.DexClassLoader');
      
      DexClassLoader.$init.implementation = function(dexPath, optimizedDir, libSearch, parent) {
        try {
          Log.info(`DexClassLoader loading: ${dexPath}`);

          if (!classLoaderStats.loaders.DexClassLoader) {
            classLoaderStats.loaders.DexClassLoader = { count: 0, paths: [] };
          }
          classLoaderStats.loaders.DexClassLoader.count++;
          classLoaderStats.loaders.DexClassLoader.paths.push(dexPath);

          const dir = getExternalDir(CONFIG.outSubdir);
          const outPath = copyFileTo(dexPath, dir, {
            operation: 'dexclassloader_copy',
            optimizedDir: optimizedDir,
            libSearch: libSearch
          });
          
          if (outPath) {
            Log.success(`Copied DexClassLoader dexPath to ${outPath}`);
            sendEvent({ 
              type: 'dump_saved', 
              payload: { 
                path: outPath, 
                kind: 'dex_path_copy', 
                src: dexPath,
                optimizedDir: optimizedDir,
                libSearch: libSearch,
                timestamp: new Date().toISOString()
              } 
            });
          }
        } catch (e) { 
          Log.debug(`Copy DexClassLoader dexPath failed: ${e.message}`); 
        }
        
        return this.$init(dexPath, optimizedDir, libSearch, parent);
      };
      
      Log.debug('DexClassLoader hook installed successfully');
    } catch (e) { 
      Log.debug(`DexClassLoader hook failed: ${e.message}`); 
    }

    try {
      const PathClassLoader = Java.use('dalvik.system.PathClassLoader');

      PathClassLoader.$init.overload('java.lang.String', 'java.lang.ClassLoader').implementation = function(path, parent) {
        try {
          Log.info(`PathClassLoader loading: ${path}`);

          if (!classLoaderStats.loaders.PathClassLoader) {
            classLoaderStats.loaders.PathClassLoader = { count: 0, paths: [] };
          }
          classLoaderStats.loaders.PathClassLoader.count++;
          classLoaderStats.loaders.PathClassLoader.paths.push(path);

          const dir = getExternalDir(CONFIG.outSubdir);
          const outPath = copyFileTo(path, dir, {
            operation: 'pathclassloader_copy'
          });
          
          if (outPath) {
            Log.success(`Copied PathClassLoader path to ${outPath}`);
            sendEvent({ 
              type: 'dump_saved', 
              payload: { 
                path: outPath, 
                kind: 'path_copy', 
                src: path,
                timestamp: new Date().toISOString()
              } 
            });
          }
        } catch (e) { 
          Log.debug(`Copy PathClassLoader path failed: ${e.message}`); 
        }
        
        return this.$init(path, parent);
      };

      try {
        PathClassLoader.$init.overload('java.lang.String', 'java.lang.String', 'java.lang.ClassLoader')
          .implementation = function(dexPath, librarySearchPath, parent) {
            try {
              Log.info(`PathClassLoader loading with lib path: ${dexPath} (lib: ${librarySearchPath})`);

              if (!classLoaderStats.loaders.PathClassLoader) {
                classLoaderStats.loaders.PathClassLoader = { count: 0, paths: [] };
              }
              classLoaderStats.loaders.PathClassLoader.count++;
              classLoaderStats.loaders.PathClassLoader.paths.push(dexPath);

              const dir = getExternalDir(CONFIG.outSubdir);
              const outPath = copyFileTo(dexPath, dir, {
                operation: 'pathclassloader_libpath_copy',
                librarySearchPath: librarySearchPath
              });
              
              if (outPath) {
                Log.success(`Copied PathClassLoader path with lib to ${outPath}`);
                sendEvent({ 
                  type: 'dump_saved', 
                  payload: { 
                    path: outPath, 
                    kind: 'path_libpath_copy', 
                    src: dexPath,
                    librarySearchPath: librarySearchPath,
                    timestamp: new Date().toISOString()
                  } 
                });
              }

              if (librarySearchPath) {
                try {
                  const File = Java.use('java.io.File');
                  const libDir = File.$new(librarySearchPath);
                  
                  if (libDir.exists() && libDir.isDirectory()) {
                    const files = libDir.listFiles();
                    
                    if (files) {
                      for (let i = 0; i < files.length; i++) {
                        const file = files[i];
                        const filePath = file.getAbsolutePath();
                        
                        if (filePath.endsWith('.so')) {
                          const libOutPath = copyFileTo(filePath, dir, {
                            operation: 'native_library_copy'
                          });
                          
                          if (libOutPath) {
                            Log.success(`Copied native library to ${libOutPath}`);
                            sendEvent({ 
                              type: 'dump_saved', 
                              payload: { 
                                path: libOutPath, 
                                kind: 'native_library_copy', 
                                src: filePath,
                                timestamp: new Date().toISOString()
                              } 
                            });
                          }
                        }
                      }
                    }
                  }
                } catch (e) {
                  Log.debug(`Failed to scan library directory: ${e.message}`);
                }
              }
            } catch (e) { 
              Log.debug(`Copy PathClassLoader path with lib failed: ${e.message}`); 
            }
            
            return this.$init(dexPath, librarySearchPath, parent);
          };
          
        Log.debug('PathClassLoader (with lib path) hook installed successfully');
      } catch (e) {
        Log.debug(`PathClassLoader (with lib path) hook failed: ${e.message}`);
      }
      
      Log.debug('PathClassLoader hook installed successfully');
    } catch (e) { 
      Log.debug(`PathClassLoader hook failed: ${e.message}`); 
    }

    try {
      const InMemoryDexClassLoader = Java.use('dalvik.system.InMemoryDexClassLoader');

      InMemoryDexClassLoader.$init.overload('java.nio.ByteBuffer', 'java.lang.ClassLoader').implementation = function(buffer, parent) {
        try {
          Log.info('InMemoryDexClassLoader created with ByteBuffer');

          if (!classLoaderStats.loaders.InMemoryDexClassLoader) {
            classLoaderStats.loaders.InMemoryDexClassLoader = { count: 0 };
          }
          classLoaderStats.loaders.InMemoryDexClassLoader.count++;

          try {
            const bytes = Java.array('byte', new Array(buffer.capacity()).fill(0));

            const originalPosition = buffer.position();

            buffer.position(0);

            buffer.get(bytes);

            buffer.position(originalPosition);

            const jsBytes = Array.prototype.slice.call(bytes);

            const fileName = generateUniqueFilename(
              'inmemory_dex', 
              'dex',
              { operation: 'inmemory_dex_dump' }
            );
            const dir = getExternalDir(CONFIG.outSubdir);
            const outPath = dir + '/' + fileName;
            
            if (writeBytesToFile(outPath, jsBytes, {
              operation: 'inmemory_dex_dump',
              size: jsBytes.length
            })) {
              Log.success(`Dumped InMemoryDexClassLoader buffer to ${outPath}`);
              sendEvent({ 
                type: 'dump_saved', 
                payload: { 
                  path: outPath, 
                  kind: 'inmemory_dex_dump', 
                  size: jsBytes.length,
                  timestamp: new Date().toISOString()
                } 
              });
            }
          } catch (e) {
            Log.debug(`Failed to dump InMemoryDexClassLoader buffer: ${e.message}`);
          }
        } catch (e) {
          Log.debug(`InMemoryDexClassLoader hook failed: ${e.message}`);
        }
        
        return this.$init(buffer, parent);
      };
      
      Log.debug('InMemoryDexClassLoader hook installed successfully');
    } catch (e) {
      Log.debug(`InMemoryDexClassLoader hook failed: ${e.message}`);
    }

    setTimeout(function() {
      Log.info(`ClassLoader Statistics: ${classLoaderStats.totalDexPaths} unique dex paths`);
      sendEvent({
        type: 'classloader_stats',
        payload: classLoaderStats
      });
    }, 5000);
  });
}


function hookMessageDigest() {
  try {
    const MessageDigest = Java.use('java.security.MessageDigest');

    const digestMap = new Map();

    MessageDigest.getInstance.overload('java.lang.String').implementation = function(algorithm) {
      const digest = this.getInstance(algorithm);
      
      try {
        digestMap.set(digest, {
          algorithm: algorithm,
          created: new Date().toISOString()
        });
        
        Log.debug(`MessageDigest created: ${algorithm}`);
      } catch (e) {
        Log.debug('Error tracking MessageDigest: ' + e.message);
      }
      
      return digest;
    };

    MessageDigest.update.overload('[B').implementation = function(input) {
      try {
        const info = digestMap.get(this) || { algorithm: this.getAlgorithm() };

        const cap = Math.min(input.length, 100);
        const inputHex = bytesToHex(input, cap);
        
        Log.debug(`MessageDigest.update (${info.algorithm}): ${inputHex}...`);
      } catch (e) {
        Log.debug('Error logging MessageDigest update: ' + e.message);
      }
      
      return this.update(input);
    };

    MessageDigest.digest.overload().implementation = function() {
      const result = this.digest();
      
      try {
        const info = digestMap.get(this) || { algorithm: this.getAlgorithm() };
        const resultHex = bytesToHex(result);
        
        Log.info(`MessageDigest.digest (${info.algorithm}): ${resultHex}`);

        sendEvent({
          type: 'crypto_hash',
          payload: {
            algorithm: info.algorithm,
            hash: resultHex,
            timestamp: new Date().toISOString()
          }
        });
      } catch (e) {
        Log.debug('Error logging MessageDigest result: ' + e.message);
      }
      
      return result;
    };
    
    Log.debug('MessageDigest hooks installed successfully');
  } catch (e) {
    Log.error('hookMessageDigest failed: ' + e.message);
  }
}


function hookMacOperations() {
  try {
    const Mac = Java.use('javax.crypto.Mac');

    const macMap = new Map();

    Mac.getInstance.overload('java.lang.String').implementation = function(algorithm) {
      const mac = this.getInstance(algorithm);
      
      try {
        macMap.set(mac, {
          algorithm: algorithm,
          created: new Date().toISOString()
        });
        
        Log.debug(`Mac created: ${algorithm}`);
      } catch (e) {
        Log.debug('Error tracking Mac: ' + e.message);
      }
      
      return mac;
    };

    Mac.doFinal.overload().implementation = function() {
      const result = this.doFinal();
      
      try {
        const info = macMap.get(this) || { algorithm: this.getAlgorithm() };
        const resultHex = bytesToHex(result);
        
        Log.info(`Mac.doFinal (${info.algorithm}): ${resultHex}`);

        sendEvent({
          type: 'crypto_mac',
          payload: {
            algorithm: info.algorithm,
            mac: resultHex,
            timestamp: new Date().toISOString()
          }
        });
      } catch (e) {
        Log.debug('Error logging Mac result: ' + e.message);
      }
      
      return result;
    };
    
    Log.debug('Mac hooks installed successfully');
  } catch (e) {
    Log.debug('hookMacOperations failed: ' + e.message);
  }
}


function hookKeyManagement() {
  try {
    const KeyGenerator = Java.use('javax.crypto.KeyGenerator');

    const keyGenMap = new Map();

    KeyGenerator.getInstance.overload('java.lang.String').implementation = function(algorithm) {
      const keyGen = this.getInstance(algorithm);
      
      try {
        keyGenMap.set(keyGen, {
          algorithm: algorithm,
          created: new Date().toISOString()
        });
        
        Log.debug(`KeyGenerator created: ${algorithm}`);
      } catch (e) {
        Log.debug('Error tracking KeyGenerator: ' + e.message);
      }
      
      return keyGen;
    };

    KeyGenerator.generateKey.implementation = function() {
      const key = this.generateKey();
      
      try {
        const info = keyGenMap.get(this) || { algorithm: this.getAlgorithm() };
        
        Log.info(`KeyGenerator.generateKey (${info.algorithm}): Generated new key`);

        sendEvent({
          type: 'crypto_key_generated',
          payload: {
            algorithm: info.algorithm,
            format: key.getFormat(),
            timestamp: new Date().toISOString()
          }
        });
      } catch (e) {
        Log.debug('Error logging KeyGenerator result: ' + e.message);
      }
      
      return key;
    };
    
    Log.debug('KeyGenerator hooks installed successfully');
  } catch (e) {
    Log.debug('hookKeyManagement failed: ' + e.message);
  }
}


function hookNioFiles(outDir) {
  try {
    const Files = Java.use('java.nio.file.Files');
    const Path = Java.use('java.nio.file.Path');


    Files.write.overload('java.nio.file.Path', '[B', '[Ljava.nio.file.OpenOption;').implementation = function(path, bytes, options) {
      try {
        const pathStr = path.toString();
        const lower = pathStr.toLowerCase();
        
        if (CONFIG.mirrorSuspiciousWrites && 
            CONFIG.suspiciousWriteExts.some(ext => lower.endsWith(ext))) {
          
          const len = bytes.length;
          const cap = Math.min(len, CONFIG.maxCaptureBytes);
          const jsBytes = Array.prototype.slice.call(bytes).slice(0, cap);

          const fileName = generateUniqueFilename(
            'nio_mirror', 
            pathStr.split('.').pop() || 'bin',
            { operation: 'nio_write_mirror', source: pathStr }
          );
          const outPath = outDir + '/' + fileName;
          
          if (writeBytesToFile(outPath, jsBytes, { 
            source: pathStr, 
            operation: 'nio_write_mirror',
            size: jsBytes.length
          })) {
            Log.success('Mirrored NIO Files.write to ' + outPath + ' from ' + pathStr);
            sendEvent({ 
              type: 'dump_saved', 
              payload: { 
                path: outPath, 
                kind: 'nio_write_mirror', 
                src: pathStr, 
                size: jsBytes.length,
                timestamp: new Date().toISOString()
              } 
            });
          }
        }
      } catch (e) {
        Log.debug('NIO mirror write failed: ' + e.message);
      }
      
      return this.write(path, bytes, options);
    };
    
    Log.debug('NIO Files hooks installed successfully');
  } catch (e) {
    Log.error('hookNioFiles failed: ' + e.message);
  }
}


function hookRandomAccessFile(outDir) {
  try {
    const RandomAccessFile = Java.use('java.io.RandomAccessFile');

    RandomAccessFile.$init.overload('java.io.File', 'java.lang.String').implementation = function(file, mode) {
      const path = file.getAbsolutePath();
      fileHandleMap.set(this, { 
        path: path, 
        type: 'RandomAccessFile',
        mode: mode,
        created: new Date().toISOString()
      });
      Log.debug('RandomAccessFile created for: ' + path + ' (mode: ' + mode + ')');
      return this.$init(file, mode);
    };

    RandomAccessFile.write.overload('[B').implementation = function(buffer) {
      const info = fileHandleMap.get(this);
      
      if (info && info.path && CONFIG.mirrorSuspiciousWrites && 
          info.mode && info.mode.includes('w')) {
        
        const path = info.path;
        const lower = path.toLowerCase();
        
        if (CONFIG.suspiciousWriteExts.some(ext => lower.endsWith(ext))) {
          try {
            const len = buffer.length;
            const cap = Math.min(len, CONFIG.maxCaptureBytes);
            const jsBytes = Array.prototype.slice.call(buffer).slice(0, cap);

            const position = this.getFilePointer();

            const fileName = generateUniqueFilename(
              'raf_mirror', 
              path.split('.').pop() || 'bin',
              { operation: 'raf_write', source: path, position: position }
            );
            const outPath = outDir + '/' + fileName;
            
            if (writeBytesToFile(outPath, jsBytes, { 
              source: path, 
              operation: 'raf_write',
              position: position,
              size: jsBytes.length
            })) {
              Log.success('Mirrored RandomAccessFile write to ' + outPath + ' from ' + path + ' at position ' + position);
              sendEvent({ 
                type: 'dump_saved', 
                payload: { 
                  path: outPath, 
                  kind: 'raf_write_mirror', 
                  src: path,
                  position: position,
                  size: jsBytes.length,
                  timestamp: new Date().toISOString()
                } 
              });
            }
          } catch (e) { 
            Log.debug('RandomAccessFile mirror write failed: ' + e.message); 
          }
        }
      }
      
      return this.write(buffer);
    };
    
    Log.debug('RandomAccessFile hooks installed successfully');
  } catch (e) {
    Log.error('hookRandomAccessFile failed: ' + e.message);
  }
}


function main() {
  try {

    sendEvent({
      type: 'hook_status',
      status: 'initializing',
      timestamp: new Date().toISOString(),
      config: CONFIG
    });

    const outDir = getExternalDir(CONFIG.outSubdir);
    Log.info(`Using output directory: ${outDir}`);

    Log.info('Installing crypto hooks...');
    hookCrypto();
    
    if (CONFIG.captureMessageDigest) {
      Log.info('Installing MessageDigest hooks...');
      hookMessageDigest();
    }
    
    Log.info('Installing Mac operation hooks...');
    hookMacOperations();
    
    Log.info('Installing key management hooks...');
    hookKeyManagement();
    
    Log.info('Installing file write hooks...');
    hookFileWrites(outDir);
    
    Log.info('Installing NIO Files hooks...');
    hookNioFiles(outDir);
    
    Log.info('Installing RandomAccessFile hooks...');
    hookRandomAccessFile(outDir);
    
    Log.info('Installing class loader hooks...');
    hookClassLoaders();

    sendEvent({
      type: 'hook_status',
      status: 'initialized',
      timestamp: new Date().toISOString(),
      outputDir: outDir,
      hooks: {
        crypto: true,
        messageDigest: CONFIG.captureMessageDigest,
        mac: true,
        keyManagement: true,
        fileWrites: true,
        nioFiles: true,
        randomAccessFile: true,
        classLoaders: true
      }
    });
    
    Log.success('All hooks installed successfully');
  } catch (e) {
    Log.error(`Main initialization failed: ${e.message}\n${e.stack}`);

    sendEvent({
      type: 'hook_status',
      status: 'error',
      error: e.message,
      stack: e.stack,
      timestamp: new Date().toISOString()
    });
  }
}

setTimeout(main, 1000);

setInterval(function() {
  sendEvent({
    type: 'heartbeat',
    timestamp: new Date().toISOString()
  });
}, 30000);
