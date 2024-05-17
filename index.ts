/**
 * @author: xingjun.xyf
 * @contact: deathmemory@163.com
 * @file: AntiDexLoader.js
 * @time: 2020/4/16 5:03 PM
 * @desc:
 */
import { DMLog } from "./utils/dmlog";
import { FCCommon } from "./utils/FCCommon";
// import {DianPing} from "./agent/dp/dp";
import { FCAnd } from "./utils/FCAnd";

// rpc.exports = {
//     f2: f_02
// };

function f_01() {
    let MainActivity = Java.use("com.ad2001.frida0x1.MainActivity");
    MainActivity["check"].implementation = function (i: any, i2: any) {
        console.log(`MainActivity.check is called: i=${i}, i2=${i2}`);
        i = 10;
        i2 = (i * 2) + 4;
        this["check"](i, i2);
    };
}
function f_02() {
    let MainActivity = Java.use("com.ad2001.frida0x2.MainActivity");
    MainActivity["get_flag"](4919);
    // MainActivity["get_flag"].implementation = function (a: any) {
    //     console.log(`MainActivity.get_flag is called: a=${a}`);
    //     a = 4919;
    //     this["get_flag"](a);
    // };
}
function f_03() {
    let Checker = Java.use("com.ad2001.frida0x3.Checker");
    Checker.code.value = 512;
    // let AnonymousClass1 = Java.use("com.ad2001.frida0x3.MainActivity$1");
    // AnonymousClass1["onClick"].implementation = function (v: any) {
    //     console.log(`AnonymousClass1.onClick is called: v=${v}`);
    //     this["onClick"](v);

    // };
}
function f_04() {
    let Check = Java.use("com.ad2001.frida0x4.Check");
    const objCheck = Check.$new();
    const r = objCheck.get_flag(1337);
    console.log(r);
    const JavaString = Java.use('java.lang.String');
    const exampleString1 = JavaString.$new(r);
    console.log(exampleString1);


}
function f_05() {
    Java.performNow(function () {
        Java.choose('com.ad2001.frida0x5.MainActivity', {
            onMatch: function (instance) {
                instance.flag(1337);
                console.log("Hook Success!");
            },
            onComplete: function () { }
        });
    });
}
function f_06() {
    Java.performNow(function () {
        Java.choose('com.ad2001.frida0x6.MainActivity', {
            onMatch: function (instance) {
                console.log("Find MainActivity instance");
                let Checker = Java.use("com.ad2001.frida0x6.Checker");
                const objCheck = Checker.$new();
                objCheck.num1.value = 1234;
                objCheck.num2.value = 4321;
                instance.get_flag(objCheck);
            },
            onComplete: function () { }
        });
    });
}
function f_07() {

    let Checker = Java.use("com.ad2001.frida0x7.Checker");
    Checker["$init"].implementation = function (a, b) {
        console.log(`Checker.$init is called: a=${a}, b=${b}`);
        a = 600;
        b = 600;
        this["$init"](a, b);
    };
}
function f_08() {
    let MainActivity = Java.use("com.ad2001.frida0x8.MainActivity");
    MainActivity["cmpstr"].implementation = function (str: any) {
        console.log(`MainActivity.cmpstr is called: str=${str}`);
        let result = this["cmpstr"](str);
        console.log(`MainActivity.cmpstr result=${result}`);
        return 1;
    };
}
function f_08_1() {
    /* Module.enumerateImports("libfrida0x8.so")
      可以获取到导出函数的名称，地址以及相关信息
    */
    let targetAddress = Module.findExportByName("libc.so", "strcmp");
    if (targetAddress !== null) {
        console.log("Strcmp Address: ", targetAddress.toString(16));
        Interceptor.attach(targetAddress, {
            onEnter: function (args: any) {
                // 在函数进入时执行的操作
                const firstArg = args[0];
                if (firstArg.readUtf8String().includes('111')) {
                    console.log(args[1].readUtf8String());
                }
            },
            onLeave: function (retval) {
                // 在函数离开时执行的操作
            }
        });
    } else {
        console.log("Target address is null.");
    }
    console.log("success!");
}
function f_09() {
    let MainActivity = Java.use("com.ad2001.a0x9.MainActivity");
    MainActivity["check_flag"].implementation = function () {
        console.log(`MainActivity.check_flag is called`);
        let result = this["check_flag"]();
        console.log(`MainActivity.check_flag result=${result}`);

        return 1337;
    };
}
function f_09_02() {
    var myModule = Process.getModuleByName('liba0x9.so');
    var check_flag = myModule.enumerateExports()[0]["address"];
    console.log("Func address = ", check_flag);
    Interceptor.attach(check_flag, {
        onEnter: function (args: any) {

        }, onLeave: function (retval) {
            console.log("Origin retval : ", retval);
            retval.replace(new NativePointer(1337));
        }
    })
}
function f_10() {
    let myModule = Process.getModuleByName('libfrida0xa.so');
    let myfunc = ['flag'];
    let a = Module.findBaseAddress("libfrida0xa.so");
    var get_flagaddress = null;
    var mvaddress = null;
    let list = myModule.enumerateExports().filter(m => m.type == 'function'
        && myfunc.some(n => m.name.includes(n)));
    for (let i = 0; i < list.length; i++) {
        const Module = list[i];
        console.log(JSON.stringify(Module));
        let address = Module["address"];
        var get_flag_ptr = new NativePointer(address);
        const get_flag = new NativeFunction(get_flag_ptr, 'char', ['int', 'int']);
        var flag = get_flag(1, 2);
        console.log(flag)
    }

}
function f_11() {
    function hook_Java_com_ad2001_frida0xb_MainActivity_getFlag() {
        let base = Module.findBaseAddress('libfrida0xb.so');
        if (base != null) {
            let hook_addr = base?.add(0x170CE)
            Interceptor.attach(hook_addr, {
                onEnter(args: any) {
                    console.log("call Java_com_ad2001_frida0xb_MainActivity_getFlag");
                    // no args
                },
                onLeave(retval) {
                    // no return
                    console.log("leave Java_com_ad2001_frida0xb_MainActivity_getFlag");
                }
            });
            var writer = new X86Writer(hook_addr);
            let isSuc = Memory.protect(hook_addr, 0x1000, "rwx");
            console.log(isSuc);
            try {
                writer.putNop();
                writer.flush();
                console.log("Success!!");
            } finally {
                writer.dispose();
            }
        }

    }

    setImmediate(hook_Java_com_ad2001_frida0xb_MainActivity_getFlag)
}
function main() {
    DMLog.d('MAIN', 'HELLO FridaContainer, please add code on the index.ts');
    f_11();
    // FCAnd.Anti.anti_ptrace();
    // FCAnd.Anti.anti_fgets();
    // and.anti.Anti.anti_fgets();

    // FCAnd.anti.anti_debug();
    /// dp
    // DianPing.anti_debug();
    // DianPing.hook_cx_stacks();
    ///
    // FCAnd.showStacks();
    // FCAnd.dump_dex_common();
    // FCAnd.Anti.anti_sslPinning("/data/local/tmp/cert-der.crt");

    // FCCommon.dump_module('libmtguard.so', '/data/data/com.dianping.v1');
    // DianPing.hook_stuffs();
    // call mtgsig
    // DianPing.test_call_mtgsig();
    // DianPing.hook_zlog();
    // FCAnd.anti.anti_debug();
    // coord: (0,203,25) | addr: Lcom.dianping.nvnetwork.tunnel.Encrypt.SocketSecureManager;->getB2keyByB2(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String; | loc: ?
    // FCAnd.traceArtMethods(['E:com.dianping.nvnetwork.tunnel.Encrypt.SocketSecureManager'], null, "122,108,111,103,46,98,105,110");  // "zlog.bin"
    // FCAnd.anti.anti_ssl_unpinning();
    // DianPing.hook_stuffs();
    // DianPing.hook_net();
    // DianPing.modify_devinfo();
    // DianPing.hook_stuffs();
    // FCAnd.hook_uri(true);
    // FCAnd.hook_url(true);
    // FCAnd.jni.traceAllJNISimply();
    // FCAnd.traceArtMethods(['M:retrofit2']);
    // rpc.exports = {
    //     test() {
    //         Java.perform(() => {
    //             FCAnd.jni.traceAllJNISimply();
    //         });
    //     }
    // }
}

if (Java.available) {
    DMLog.i("JAVA", "available");
    Java.perform(function () {
        main();
    });

}

if (ObjC.available) {
    DMLog.i("ObjC", "available");
    FCCommon.printModules();
    FCCommon.dump_module("Hopper Disassembler v4", "/Users/dmemory/Downloads/");
}


