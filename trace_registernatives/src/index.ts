import { JNIInterceptor } from "jnitrace-engine";
import { JNILibraryWatcher } from "jnitrace-engine";
import { Config } from "jnitrace-engine";
import { ConfigBuilder } from "jnitrace-engine";
import { JNINativeReturnValue } from "jnitrace-engine";


let config: Config | null = null;
var library_name = ""

JNILibraryWatcher.setCallback({
    onLoaded(path: string): void {
        if (!Config.initialised()) {
            var op = recv("library", function(value) {
                library_name = value.name;
                const builder : ConfigBuilder = new ConfigBuilder();
                builder.libraries = [ library_name ];
                builder.env = true;
                builder.vm = false;
                config = builder.build();
            });
            op.wait();
        }
    }
});


JNIInterceptor.attach("RegisterNatives", {
    onEnter(args: NativeArgumentValue[]) {
        var base = Module.getBaseAddress(library_name);

        this.env = args[0];
        this.clazz = args[1];
        this.methods = args[2];
        this.nMethods = args[3];

        const GetMethodID = new NativeFunction(
            this.env.readPointer().add(132).readPointer(),
            "pointer", ["pointer", "pointer", "pointer", "pointer"]
        );

        const CallObjectMethod = new NativeFunction(
            this.env.readPointer().add(136).readPointer(),
            "pointer", ["pointer", "pointer", "pointer"]
        );

        const GetStringUTFChars = new NativeFunction(
            this.env.readPointer().add(676).readPointer(),
            "pointer", ["pointer", "pointer", "pointer"]
        );

        var mid = GetMethodID(
            this.env,
            this.clazz,
            Memory.allocUtf8String("getClass"),
            Memory.allocUtf8String("()Ljava/lang/Class;")
        );

        var cls = CallObjectMethod(this.env, this.clazz, mid);

        mid = GetMethodID(
            this.env,
            cls,
            Memory.allocUtf8String("getName"),
            Memory.allocUtf8String("()Ljava/lang/String;")
        );

        var class_name = CallObjectMethod(this.env, this.clazz, mid);
        var class_name_str = (<NativePointer>GetStringUTFChars(
            this.env, class_name, NULL)).readUtf8String();

        send({
            "type": "registernatives",
            "clazz": class_name_str,
            "methods": this.methods.sub(base),
            "nMethods": this.nMethods
        });
    },
    onLeave(retval) {}
});
