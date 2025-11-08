/*
Hook fork to prevent child processes from interrupting Frida
Returns -1 with errno EPERM
*/
(() => {
    const forkSymbol = Module.findGlobalExportByName("fork");
    if (!forkSymbol) {
        console.warn("[-] fork() not found");
        return;
    }
    const errnoPtr = (() => {
        const errnoLocation = Module.findGlobalExportByName("__errno_location");
        return errnoLocation ? new NativeFunction(errnoLocation, "pointer", [])() : null;
    })();

    const safeForkHandler = new NativeCallback(() => {
        console.warn("[!] Fork intercepted - returning -1 (EPERM)");
        if (errnoPtr) errnoPtr.writeS32(1);
        return -1;
    }, 'int', []);

    Interceptor.replace(forkSymbol, safeForkHandler);
    console.warn("[+] Fork hook: ACTIVE");
})();

/* Enter your target package name here */
const TARGET_PKG = "com.ldjSxw.heBbQd";
const SAFE_DIR = `/data/local/tmp/dex_dumps/`;

const DETECTION_LIBRARIES = [
    { pattern: "libdexprotector", message: "DexProtector: https://licelus.com" },
    { pattern: "libjiagu", message: "Jiagu360: https://jiagu.360.cn" },
    { pattern: "libAppGuard", message: "AppGuard: http://appguard.nprotect.com" },
    { pattern: "libDexHelper", message: "Secneo: http://www.secneo.com" },
    { pattern: "libsecexe|libsecmain|libSecShell", message: "Bangcle: https://github.com/woxihuannisja/Bangcle" },
    { pattern: "libprotectt|libapp-protectt", message: "Protectt: https://www.protectt.ai" },
    { pattern: "libkonyjsvm", message: "Kony: http://www.kony.com/" },
    { pattern: "libnesec", message: "Yidun: https://dun.163.com/product/app-protect" },
    { pattern: "libcovault", message: "AppSealing: https://www.appsealing.com/" },
    { pattern: "libpairipcore", message: "Pairip: https://github.com/rednaga/APKiD/issues/329" }
];

function hookDlopen() {
    return new Promise((resolve, reject) => {
        try {
            const isArm = Process.arch === "arm" ? "linker" : "linker64";
            const reg = Process.arch === "arm" ? "r0" : "x0";
            const linker = Process.findModuleByName(isArm);

            if (!linker) {
                reject(new Error("Linker module not found"));
                return;
            }

            let resolved = false;
            const resolveOnce = () => {
                if (!resolved) {
                    resolved = true;
                    resolve();
                }
            };

            const sym = linker.enumerateExports().find(e => e.name.includes('android_dlopen_ext'));
            Interceptor.attach(sym.address, {
                onEnter(args) {
                    const libPath = this.context[reg].readUtf8String();
                    if (!libPath) return;

                    for (const { pattern, message } of DETECTION_LIBRARIES) {
                        if (new RegExp(pattern).test(libPath)) {
                            console.warn(`\n[*] Packer Detected: ${message}`);
                            resolveOnce();
                            return;
                        }
                    }
                }
            });
            setTimeout(resolveOnce, 3000);
        } catch (e) {
            reject(new Error("Unsupported architecture/emulator"));
        }
    });
}

function processDex(Buf, C, Path) {
    // Ensure the buffer is valid
    if (!Buf || Buf.byteLength < 8) {
        console.error(`[!] Invalid buffer for classes${C - 1}.dex`);
        return;
    }
    const DumpDex = Buf instanceof Uint8Array ? Buf : new Uint8Array(Buf);
    const Count = C - 1;
    // Signatures for detecting CDEX, Empty Header, and Wiped Header
    const CDEX_SIGNATURE = [0x63, 0x64, 0x65, 0x78, 0x30, 0x30, 0x31];
    const EMPTY_HEADER = [0x00, 0x00, 0x00, 0x00];
    const WIPED_HEADER = [0x64];
    // Detect CDEX
    if (CDEX_SIGNATURE.every((val, i) => DumpDex[i] == val)) {
        console.warn(`[*] classes${Count}.dex is a Compact Dex (CDEX). Ignoring.`);
        return;
    }
    // Detect Empty Header (DexProtector)
    if (EMPTY_HEADER.every((val, i) => DumpDex[i] == val) && DumpDex[7] == 0x00) {
        console.warn(`[*] 00000 Header detected in classes${Count}.dex, possible DexProtector.`);
        writeDexFile(Count, Buf, Path, 0);
        return;
    }
    // Detect Wiped Header (Obfuscation/Tampered)
    if (DumpDex[0] == 0x00 || WIPED_HEADER.every((val, i) => DumpDex[i] != val)) {
        console.warn(`[*] Wiped Header detected, classes${Count}.dex might be interesting.`);
        writeDexFile(Count, Buf, Path, 0);
        return;
    }
    // Default: Consider it as a normal Dex file
    writeDexFile(Count, Buf, Path, 1);
}

function writeDexFile(count, buffer, path, isValid) {
    try {
        const file = new File(path, "wb");
        file.write(buffer);
        file.close();
        console.log(`[Dex${count}] Saved to: ${path} ${isValid ? '(valid)' : '(modified)'}`);
    } catch (error) {
        console.error(`[!] Failed to save Dex${count} to ${path}: ${error.message}`);
    }
}

function findDefineClass(libart) {
    const matcher = /ClassLinker.*DefineClass.*Thread.*DexFile/;
    const search = (items, type) => items.find(item => matcher.test(item.name))?.address;

    return search(libart.enumerateSymbols(), 'symbols') ||
        search(libart.enumerateImports(), 'imports') ||
        search(libart.enumerateExports(), 'exports');
}

function dumpDex() {
    const libart = Process.findModuleByName("libart.so");
    if (!libart) return console.error("[!] libart.so not found");
    const defineClassAddr = findDefineClass(libart);
    console.warn("[*] DefineClass found at : ", defineClassAddr);
    if (!defineClassAddr) return console.error("[!] DefineClass not found");
    const seenDex = new Set();
    let dexCount = 1;

    Interceptor.attach(defineClassAddr, {
        onEnter(args) {
            const dexFilePtr = args[5];
            const base = dexFilePtr.add(Process.pointerSize).readPointer();
            const size = dexFilePtr.add(Process.pointerSize * 2).readUInt();
            if (seenDex.has(base.toString())) return;
            seenDex.add(base.toString());
            const dexBuffer = base.readByteArray(size);
            if (!dexBuffer || dexBuffer.byteLength !== size) return;
            const path = `${SAFE_DIR}classes${dexCount}.dex`;
            processDex(dexBuffer, dexCount++, path);
        }
    });
}

async function main() {
    // 1. 부가 기능: dlopen 후킹 시도 (실패해도 괜찮음)
    try {
        await hookDlopen();
        console.warn("[*] dlopen hook established.");
    } catch (e) {
        console.error(`[!] dlopen hook failed (continuing anyway): ${e.message}`);
    }

    // 2. 핵심 기능: DEX 덤프 실행 (이것이 진짜 목표)
    try {
        console.warn("[*] Starting main dex dump hook...");
        dumpDex();
        console.warn("[*] Dex dump hook is now active.");
    } catch (e) {
        console.error(`[!] dumpDex() failed to start: ${e.message}`);
    }
}

setImmediate(main);
