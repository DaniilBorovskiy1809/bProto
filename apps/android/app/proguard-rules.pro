# Keep the JNI entry points: they are resolved by name at runtime, so R8 cannot
# see the references. The native symbols are Java_dev_bproto_Bproto_*.
-keepclasseswithmembernames,includedescriptorclasses class dev.bproto.Bproto {
    native <methods>;
}
-keep class dev.bproto.Bproto { *; }
