#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![feature(offset_of)]

#![no_std]

use core::ptr;
use core::arch::x86_64::_rdtsc;
use core::arch::asm;

include!{"./bindings.rs"}

static mut DEV: Option<WOLFTPM2_DEV> = None;
static mut SIGNING_KEY: Option<WOLFTPM2_KEY> = None;

const nullHandle: u32 = 0x40000007;
const ownerHandle: u32 = 0x40000001;

const TPM_ECC_NIST_P256: u16 = 0x0003;
const TPM_ALG_SHA256: u16 = 0x000B;
const TPM_ALG_RSASSA: u16 = 0x0014;
const TPM_ALG_ECDSA: u16 = 0x0018;
const TPM_ALG_ECC: u16 = 0x0023;

const signingKeyAttributes: u32 = 0x0 |
                // 0x0000_0002 | // TPMA_OBJECT_fixedTPM = 0x00000002
                // 0x0000_0010 | // TPMA_OBJECT_fixedParent = 0x00000010
                0x0000_0020 | // TPMA_OBJECT_sensitiveDataOrigin = 0x00000020
                0x0000_0040 | // TPMA_OBJECT_userWithAuth = 0x00000040
                0x0000_0400 | // TPMA_OBJECT_noDA = 0x00000400
                0x0004_0000;  // TPMA_OBJECT_sign = 0x00040000

fn isECC(key: &WOLFTPM2_KEY) -> bool {
    return key.pub_.publicArea.type_ == TPM_ALG_ECC;
}

pub fn init() -> usize {
    // TODO check if already initialized / is not None
    unsafe {
        DEV = Some(WOLFTPM2_DEV::default());

        let Some(ref mut dev) = DEV else { return usize::MAX; };

        let ret = wolfTPM2_Init(dev, None, ptr::null_mut());
        log::info!("wolfTPM2_Init: {:?}", ret);

        let ret = wolfTPM2_SelfTest(dev);
        log::info!("wolfTPM2_SelfTest: {:?}", ret);

        let ret = create_null_signing_key(true);
        log::info!("create_null_signing_key: {:?}", ret);

        return ret as usize;
    }
}

fn create_null_signing_key(isECC: bool) -> usize {
    log::info!("Creating signing key under null hierarchy");

    unsafe {
        let Some(ref mut dev) = DEV else {
            log::info!("TPM2 device not initialized");
            return usize::MAX;
        };

        // TODO check if initialized
        SIGNING_KEY = Some(WOLFTPM2_KEY::default());
        let Some(ref mut signing_key) = SIGNING_KEY else {
            log::info!("signing_key not created");
            return usize::MAX;
        };

        let signingTemplate = &mut TPMT_PUBLIC::default();

        if isECC {
            let ret = wolfTPM2_GetKeyTemplate_ECC(signingTemplate, signingKeyAttributes, TPM_ECC_NIST_P256, TPM_ALG_ECDSA);
            log::info!("wolfTPM2_GetKeyTemplate_ECC: {:?}", ret);
        } else {
            let ret = wolfTPM2_GetKeyTemplate_RSA(signingTemplate, signingKeyAttributes);
            log::info!("wolfTPM2_GetKeyTemplate_RSA: {:?}", ret);
        }

        let ret = wolfTPM2_CreatePrimaryKey(dev, signing_key, nullHandle, signingTemplate, ptr::null_mut(), 0);
        log::info!("new wolfTPM2_CreatePrimaryKey: {:?}", ret);

        return ret as usize;
    }
}

pub fn self_test() -> usize {
    unsafe {
        let Some(ref mut dev) = DEV else { return usize::MAX; };
        return wolfTPM2_SelfTest(dev) as usize;
    }
}

pub fn get_signing_key(public_key: &mut [u8]) -> usize {
    unsafe {
        let Some(ref mut signing_key) = SIGNING_KEY else {
            log::info!("signing_key not created");
            return usize::MAX;
        };

        // Determine type of key.
        if isECC(signing_key) {
            let (x_size, y_size) = (signing_key.pub_.publicArea.unique.ecc.x.size as usize, signing_key.pub_.publicArea.unique.ecc.y.size as usize);
            public_key.copy_from_slice(&signing_key.pub_.publicArea.unique.ecc.x.buffer[..x_size]);
            public_key[x_size..].copy_from_slice(&signing_key.pub_.publicArea.unique.ecc.y.buffer[..y_size]);
            return x_size + y_size;
        } else {
            let n = signing_key.pub_.publicArea.unique.rsa.size as usize;
            public_key.copy_from_slice(&signing_key.pub_.publicArea.unique.rsa.buffer[..n]);
            return n;
        }
    }
}

pub fn print_signing_key() {
    // TODO will this actually throw an error if SIGNING_KEY is None?
    unsafe {
        let Some(ref mut signing_key) = SIGNING_KEY else {
            log::info!("signing_key not created");
            return;
        };

        if isECC(signing_key) {
            let (x_size, y_size) = (signing_key.pub_.publicArea.unique.ecc.x.size as usize, signing_key.pub_.publicArea.unique.ecc.y.size as usize);
            log::info!("signing_key.ecc.x: {:?}", &signing_key.pub_.publicArea.unique.ecc.x.buffer[..x_size]);
            log::info!("signing_key.ecc.y: {:?}", &signing_key.pub_.publicArea.unique.ecc.y.buffer[..y_size]);
        } else {
            log::info!("signing_key.rsa.size: {:?}", signing_key.pub_.publicArea.unique.rsa.size);
            log::info!("signing_key.rsa.exponent: {:?}", signing_key.pub_.publicArea.parameters.rsaDetail.exponent);
            log::info!("signing_key.rsa.buff: {:?}", signing_key.pub_.publicArea.unique.rsa.buffer);
        }
    }
}

pub fn sign(digest: &[u8], sig: &mut [u8]) -> i32 {
    // TODO assert digest is 32 bytes, sig is 256 bytes
    let sigSz: &mut i32 = &mut (sig.len() as i32);
    let digestSz: &mut i32 = &mut (digest.len() as i32);

    unsafe {
        let Some(ref mut dev) = DEV else {
            log::info!("TPM2 device not initialized");
            return i32::MAX;
        };

        let Some(ref mut signing_key) = SIGNING_KEY else {
            log::info!("signing_key not created");
            return i32::MAX;
        };

        let ret: i32;
        if isECC(signing_key) {
            ret = wolfTPM2_SignHashScheme(dev, signing_key, digest.as_ptr(), *digestSz, sig.as_mut_ptr(), sigSz as *mut i32, TPM_ALG_ECDSA, TPM_ALG_SHA256);
        } else {
            ret = wolfTPM2_SignHashScheme(dev, signing_key, digest.as_ptr(), *digestSz, sig.as_mut_ptr(), sigSz as *mut i32, TPM_ALG_RSASSA, TPM_ALG_SHA256);
        }

        log::info!("wolfTPM2_SignHashScheme: {:?}", ret);

        return *sigSz;
    }
}

pub fn sign_e2e_benchmark(digest: &[u8], sig: &mut [u8]) -> u64 {
    // TODO assert digest is 32 bytes, sig is 256 bytes
    let sigSz: &mut i32 = &mut (sig.len() as i32);
    let digestSz: &mut i32 = &mut (digest.len() as i32);

    unsafe {
        let Some(ref mut dev) = DEV else {
            log::info!("TPM2 device not initialized");
            return u64::MAX;
        };

        let Some(ref mut signing_key) = SIGNING_KEY else {
            log::info!("signing_key not created");
            return u64::MAX;
        };

        let signAlg = if isECC(signing_key) { TPM_ALG_ECDSA } else { TPM_ALG_RSASSA };

        asm! ("mfence;");
        let start = unsafe { _rdtsc() };
        let ret = wolfTPM2_SignHashScheme(dev, signing_key, digest.as_ptr(), *digestSz, sig.as_mut_ptr(), sigSz as *mut i32, signAlg, TPM_ALG_SHA256);
        let end = unsafe { _rdtsc() };
        asm! ("mfence;");
        return end - start;
    }
}

pub fn hash_and_sign(data: &[u8], sig: &mut [u8]) -> i32 {
    let hash = &mut WOLFTPM2_HASH::default();
    let digest = &mut [0; 32];
    let digestSz = &mut (digest.len() as u32);

    unsafe {
        let Some(ref mut dev) = DEV else {
            log::info!("TPM2 device not initialized");
            return i32::MAX;
        };

        let ret = wolfTPM2_HashStart(dev, hash, 0x000B, ptr::null_mut(), 0);
        log::info!("wolfTPM2_HashStart: {:?}", ret);

        let ret = wolfTPM2_HashUpdate(dev, hash, data.as_ptr(), data.len().try_into().unwrap());
        log::info!("wolfTPM2_HashUpdate: {:?}", ret);

        let ret = wolfTPM2_HashFinish(dev, hash, digest.as_mut_ptr(), digestSz);
        log::info!("wolfTPM2_HashFinish: {:?}", ret);

        log::info!("Hash: {:?}", digest);

        return sign(digest, sig);
    }
}

pub fn hash_and_sign_zeroes() {
    // TODO will this actually throw an error if SIGNING_KEY is None?
    unsafe {
        let Some(ref mut dev) = DEV else {
            log::info!("TPM2 device not initialized");
            return;
        };

        let Some(ref mut signing_key) = SIGNING_KEY else {
            log::info!("signing_key not created");
            return;
        };

        let data = [0; 32];

        if isECC(signing_key) {
            let sig = &mut [0; 64];
            let _ = hash_and_sign(&data, sig);
            log::info!("Sig: {:?}", sig);
        } else {
            let sig = &mut [0; 256];
            let _ = hash_and_sign(&data, sig);
            log::info!("Sig: {:?}", sig);
        }
    }
}

pub fn ecschnorr_test() -> usize {
    // let dev: &mut WOLFTPM2_DEV = &mut WOLFTPM2_DEV::default();
    let publicTemplate = &mut TPMT_PUBLIC::default();
    // let objectAttributes = 0x40000; // TPMA_OBJECT_sign  = 0x40000
    // let curve = 0x0003; // TPM_ECC_NIST_P256  = 0x0003,
    // let sigScheme = 0x001C; // TPM_ALG_ECSCHNORR = 0x001C,
    // let sigScheme = 0x0018; // TPM_ALG_ECDSA = 0x0018,
    let sigScheme = 0x0001; // TPM_ALG_RSA = 0x0001,

    let storage_key = &mut WOLFTPM2_KEY::default();
    let storage_handle = 0x8100_0200;
    // let primary_key = &mut WOLFTPM2_KEY::default();
    let signing_key = &mut WOLFTPM2_KEY::default();

    let signingTemplate = &mut TPMT_PUBLIC::default();

    let digest = [0; 32];

    let sig = &mut [0; 512];
    let sig_size = &mut 512;

    unsafe {
        let Some(ref mut dev) = DEV else { return usize::MAX; };

        // let _ret = wolfTPM2_Init(dev, None, ptr::null_mut());
        // log::info!("wolfTPM2_Init: {:?}", _ret);
        // let _ret = wolfTPM2_GetKeyTemplate_ECC(publicTemplate, objectAttributes, curve, sigScheme);
        // let _ret = wolfTPM2_GetKeyTemplate_RSA_SRK(publicTemplate);
        // log::info!("wolfTPM2_GetKeyTemplate_RSA_SRK: {:?}", _ret);

        let _ret = wolfTPM2_CreateSRK(dev, storage_key, sigScheme, ptr::null_mut(), 0);
        log::info!("wolfTPM2_CreateSRK: {:?}", _ret);

        let _ret = wolfTPM2_NVStoreKey(dev, ownerHandle, storage_key, storage_handle);
        log::info!("wolfTPM2_NVStoreKey: {:?}", _ret);

        // let _ret = wolfTPM2_CreatePrimaryKey(dev, primary_key, primaryHandle, publicTemplate, ptr::null_mut(), 0);
        // log::info!("wolfTPM2_CreatePrimaryKey: {:?}", _ret);

        let _ret = wolfTPM2_GetKeyTemplate_RSA(signingTemplate, signingKeyAttributes);
        log::info!("wolfTPM2_GetKeyTemplate_RSA: {:?}", _ret);

        // let parent = wolfTPM2_GetHandleRefFromKey(primary_key);
        // log::info!("wolfTPM2_GetHandleRefFromKey: {:?}", _ret);

        let handle = wolfTPM2_GetHandleRefFromKey(storage_key);

        let _ret = wolfTPM2_CreateAndLoadKey(dev, signing_key, handle, signingTemplate, ptr::null_mut(), 0);
        log::info!("wolfTPM2_CreateAndLoadKey: {:?}", _ret);

        let _ret = wolfTPM2_SignHashScheme(dev, signing_key, digest.as_ptr(), 32, sig.as_mut_ptr(), sig_size, 0x0014, 0x000B); 
        log::info!("wolfTPM2_SignHash: {:?}", _ret);

        log::info!("sig: {:?}", sig);
        log::info!("sig_size: {:?}", sig_size);

        log::info!("keysize: {:?}", signing_key.pub_.size);
        log::info!("signing_key.rsa.size: {:?}", signing_key.pub_.publicArea.unique.rsa.size);
        log::info!("signing_key.rsa.exponent: {:?}", signing_key.pub_.publicArea.parameters.rsaDetail.exponent);
        log::info!("signing_key.rsa.buff: {:?}", signing_key.pub_.publicArea.unique.rsa.buffer);
        // log::info!("signing_key.x.size: {:?}", signing_key.pub_.publicArea.unique.ecc.x.size);
        // log::info!("signing_key.x.buff: {:?}", signing_key.pub_.publicArea.unique.ecc.x.buffer);
        // log::info!("signing_key.y.size: {:?}", signing_key.pub_.publicArea.unique.ecc.y.size);
        // log::info!("signing_key.y.buff: {:?}", signing_key.pub_.publicArea.unique.ecc.y.buffer);

        let new_key = &mut WOLFTPM2_KEY::default();
        let _ret = wolfTPM2_GetKeyTemplate_RSA(publicTemplate, signingKeyAttributes);
        log::info!("new wolfTPM2_GetKeyTemplate_RSA: {:?}", _ret);
        let _ret = wolfTPM2_CreatePrimaryKey(dev, new_key, ownerHandle, publicTemplate, ptr::null_mut(), 0);
        log::info!("new wolfTPM2_CreatePrimaryKey: {:?}", _ret);
        let _ret = wolfTPM2_SignHashScheme(dev, new_key, digest.as_ptr(), 32, sig.as_mut_ptr(), sig_size, 0x0014, 0x000B);
        log::info!("new wolfTPM2_SignHashScheme: {:?}", _ret);
        log::info!("new sig: {:?}", sig);
        log::info!("new sig_size: {:?}", sig_size);

        log::info!("new keysize: {:?}", new_key.pub_.size);
        log::info!("new signing_key.rsa.size: {:?}", new_key.pub_.publicArea.unique.rsa.size);
        log::info!("new signing_key.rsa.exponent: {:?}", new_key.pub_.publicArea.parameters.rsaDetail.exponent);
        log::info!("new signing_key.rsa.buff: {:?}", new_key.pub_.publicArea.unique.rsa.buffer);

        return 0;
    }
}

pub fn mftr_info(buff: &mut [u8]) -> usize {
    let mut written: usize = 0;
    let caps = &mut WOLFTPM2_CAPS::default();

    unsafe {
        let Some(ref mut dev) = DEV else { return usize::MAX; };

        if wolfTPM2_Init(dev, None, ptr::null_mut()) != 0 {
            return written
        }

        if wolfTPM2_GetCapabilities(dev, caps) != 0 {
            return written
        }

        let mut count = 0;
        for &byte in caps.mfgStr.iter() {
            if byte == 0 {
                break;
            }

            if count < buff.len() {
                buff[count] = byte as u8;
                count += 1;
            } else {
                break;
            }
        }

        written = count;
        count = 0;

        for &byte in caps.vendorStr.iter() {
            if byte == 0 {
                break;
            }

            if written + count < buff.len() {
                buff[written+count] = byte as u8;
                count += 1;
            } else {
                break;
            }
        }

        written + count
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
