#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::ptr;

extern crate log;

include!{"./bindings.rs"}

impl TPM2_CTX {
    pub fn new() -> Self {
        Self {
            ioCb: None,
            userCtx: ptr::null_mut(),
            rng: WC_RNG { seed: OS_Seed { fd: 0 }, heap: ptr::null_mut(), drbg: &mut DRBG { _address: 0 }, status: 0},
            locality: 0,
            caps: 0,
            did_vid: 0,
            session: ptr::null_mut(),
            cmdBuf: [0; 4096],
            rid: 0,
            _bitfield_align_1: [0; 0],
            _bitfield_1: __BindgenBitfieldUnit::new([0]),
            __bindgen_padding_0: [0; 3],
        }
    }
}

impl TPM2_AUTH_SESSION {
    pub fn new() -> Self {
        Self {
            sessionHandle: 0,
            nonceCaller: TPM2B_DIGEST { size: 0, buffer: [0; 64] },
            sessionAttributes: 0,
            auth: TPM2B_DIGEST { size: 0, buffer: [0; 64] },
            nonceTPM: TPM2B_DIGEST { size: 0, buffer: [0; 64] },
            symmetric: TPMT_SYM_DEF { algorithm: 0, keyBits: TPMU_SYM_KEY_BITS { aes: 0 }, mode: TPMU_SYM_MODE { aes: 0 }},
            authHash: 0,
            name: TPM2B_NAME { size: 0, name: [0; 68] },
        }
    }
}

impl WOLFTPM2_DEV {
    pub fn new() -> Self {
        Self {
            ctx: TPM2_CTX::new(),
            session: [TPM2_AUTH_SESSION::new(), TPM2_AUTH_SESSION::new(), TPM2_AUTH_SESSION::new()],
        }
    }
}

fn self_test() {
    log::warn!("Hello, world!");

    let dev = &mut WOLFTPM2_DEV::new();
    let ioCb = None;
    let userCtx = ptr::null_mut();

    let caps = &mut WOLFTPM2_CAPS::default();

    unsafe {
        let mut ret = wolfTPM2_Init(dev, ioCb, userCtx);
        log::warn!("wolfTPM2_Init() = {:?}", ret);
        ret = wolfTPM2_SelfTest(dev);
        log::warn!("wolfTPM2_SelfTest(): {:?}", ret);
        ret = wolfTPM2_GetCapabilities(dev, caps);
        log::warn!("wolfTPM2_GetCapabilities: {:?}", ret);
        log::warn!("mfgStr: {:?}", caps.mfgStr);
        log::warn!("vendorStr: {:?}", caps.vendorStr);
        log::warn!("tpmType: {:?}", caps.tpmType);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}
