# vAccel Kata build

To use the builtin vAccel RPC agent, build Kata with:

```sh
LIBC=gnu make -C src/runtime-rs USE_BUILTIN_VACCEL=true
```

The vendored OpenSSL from `nydus` conflicts with the system OpenSSL. To
successfully use vAccel with cURL support, force-disable vendored OpenSSL:

```sh
LIBC=gnu make -C src/runtime-rs USE_BUILTIN_VACCEL=true OPENSSL_NO_VENDOR=1
```
