//! Two-phase carrier lifecycle: bind -> protect(fd) in Java -> start.
use jni::{
    JNIEnv,
    objects::{JByteArray, JObject, JString},
    sys::{jint, jlong},
};
use vpn_core::transport::quic::{EchSettings, QuicBridge, QuicTransport};

struct Carrier {
    prepared: Option<QuicTransport>,
    bridge: Option<QuicBridge>,
    runtime: tokio::runtime::Runtime,
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_bproto_Bproto_quicBind(
    _env: JNIEnv,
    _this: JObject,
    ipv6: jint,
) -> jlong {
    let result = (|| {
        let local = if ipv6 == 0 { "0.0.0.0:0" } else { "[::]:0" };
        let prepared = QuicTransport::bind(local.parse().unwrap()).map_err(|e| e.to_string())?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .map_err(|e| e.to_string())?;
        Ok::<_, String>(Box::new(Carrier {
            prepared: Some(prepared),
            bridge: None,
            runtime,
        }))
    })();
    match result {
        Ok(handle) => Box::into_raw(handle) as jlong,
        Err(error) => {
            crate::set_error(&error);
            0
        }
    }
}

/// Caller serializes lifecycle methods and never reuses a closed handle.
#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_bproto_Bproto_quicSocketFd(
    _env: JNIEnv,
    _this: JObject,
    handle: jlong,
) -> jint {
    if handle == 0 {
        return -1;
    }
    let carrier = unsafe { &*(handle as *const Carrier) };
    carrier
        .prepared
        .as_ref()
        .map_or(-1, QuicTransport::socket_fd)
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_bproto_Bproto_quicStart(
    mut env: JNIEnv,
    _this: JObject,
    handle: jlong,
    server: JString,
    hostname: JString,
    token: JString,
    ech: JByteArray,
    expires: jlong,
) -> jint {
    if handle == 0 {
        return -1;
    }
    let carrier = unsafe { &mut *(handle as *mut Carrier) };
    let result = (|| {
        let server = super::read_string(&mut env, &server)?
            .parse()
            .map_err(|_| "invalid QUIC endpoint")?;
        let hostname = super::read_string(&mut env, &hostname)?;
        let token = super::read_string(&mut env, &token)?;
        let bytes = env
            .convert_byte_array(&ech)
            .map_err(|_| "Invalid ECH bytes")?;
        let ech = if bytes.is_empty() && expires == 0 {
            None
        } else {
            if expires <= 0 {
                return Err("Invalid ECH expiry".to_string());
            }
            Some(EchSettings {
                config_list: bytes,
                expires_unix_secs: expires as u64,
            })
        };
        let prepared = carrier.prepared.take().ok_or("carrier already started")?;
        let bridge = carrier
            .runtime
            .block_on(prepared.connect_with_ech(server, &hostname, &token, None, ech))
            .map_err(|e| e.to_string())?;
        let port = bridge.local_port();
        carrier.bridge = Some(bridge);
        Ok::<_, String>(port as jint)
    })();
    match result {
        Ok(port) => port,
        Err(error) => {
            crate::set_error(&error);
            -1
        }
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_bproto_Bproto_quicAlive(
    _env: JNIEnv,
    _this: JObject,
    handle: jlong,
) -> jint {
    if handle == 0 {
        return 0;
    }
    let carrier = unsafe { &*(handle as *const Carrier) };
    i32::from(
        carrier
            .bridge
            .as_ref()
            .is_some_and(|bridge| !bridge.is_finished()),
    )
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_dev_bproto_Bproto_quicClose(
    _env: JNIEnv,
    _this: JObject,
    handle: jlong,
) {
    if handle != 0 {
        drop(unsafe { Box::from_raw(handle as *mut Carrier) });
    }
}
