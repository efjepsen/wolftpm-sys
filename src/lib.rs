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

// Helper function to determine if a key uses ECC, or not (is RSA).
fn isECC(key: &WOLFTPM2_KEY) -> bool {
    return key.pub_.publicArea.type_ == TPM_ALG_ECC;
}

// Initializes the TPM interface & creates a key in the null hierarhy
pub fn init() -> usize {
    // Returns zero on success.
    unsafe {
        DEV = Some(WOLFTPM2_DEV::default());

        let Some(ref mut dev) = DEV else { return usize::MAX; };

        let ret = wolfTPM2_Init(dev, None, ptr::null_mut());
        log::trace!("wolfTPM2_Init: {:?}", ret);

        let ret = wolfTPM2_SelfTest(dev);
        log::info!("wolfTPM2_SelfTest: {:?}", ret);

        let ret = create_null_signing_key(true);
        log::trace!("create_null_signing_key: {:?}", ret);

        return ret as usize;
    }
}

// Create a key under the null hierarchy, which is lost on every power reset.
// This is useful for testing so as to not clutter your TPM.
// In a real deployment, you would want to choose a specific handle and store
// signing keys there.
fn create_null_signing_key(isECC: bool) -> usize {
    log::trace!("Creating signing key under null hierarchy");

    unsafe {
        let Some(ref mut dev) = DEV else {
            log::error!("TPM2 device not initialized");
            return usize::MAX;
        };

        SIGNING_KEY = Some(WOLFTPM2_KEY::default());
        let Some(ref mut signing_key) = SIGNING_KEY else {
            log::error!("signing_key not created");
            return usize::MAX;
        };

        let signingTemplate = &mut TPMT_PUBLIC::default();

        // NOTE: In order to use the TPM Quote functionality, use the signing
        // keys templates for AIKs (Attestation Identity Key) below

        if isECC {
            // let ret = wolfTPM2_GetKeyTemplate_ECC_AIK(signingTemplate);
            let ret = wolfTPM2_GetKeyTemplate_ECC(signingTemplate, signingKeyAttributes, TPM_ECC_NIST_P256, TPM_ALG_ECDSA);
            log::trace!("wolfTPM2_GetKeyTemplate_ECC: {:?}", ret);
        } else {
            // let ret = wolfTPM2_GetKeyTemplate_RSA_AIK(signingTemplate);
            let ret = wolfTPM2_GetKeyTemplate_RSA(signingTemplate, signingKeyAttributes);
            log::trace!("wolfTPM2_GetKeyTemplate_RSA: {:?}", ret);
        }

        let ret = wolfTPM2_CreatePrimaryKey(dev, signing_key, nullHandle, signingTemplate, ptr::null_mut(), 0);
        log::info!("wolfTPM2_CreatePrimaryKey: {:?}", ret);

        return ret as usize;
    }
}

// Used to benchmark time to produce a quote, comparable to signing.
pub fn quote() -> usize {
    unsafe {
        let Some(ref mut signing_key) = SIGNING_KEY else {
            log::error!("signing_key not created");
            return usize::MAX;
        };
        let mut in_: Quote_In = Quote_In::default();

        let mut pcr = TPML_PCR_SELECTION::default();
        let mut pcrsel: [u8; 17] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 23];

        TPM2_SetupPCRSelArray(&mut pcr, TPM_ALG_SHA256, pcrsel.as_mut_ptr() , 17);
        in_.signHandle = signing_key.handle.hndl;
        in_.qualifyingData = TPM2B_DATA::default(); // nonce
        in_.inScheme = signing_key.pub_.publicArea.parameters.eccDetail.scheme;
        in_.PCRselect = pcr;

        let mut out_: Quote_Out = Quote_Out::default();

        let ret = TPM2_Quote(&mut in_, &mut out_);
        log::info!("tpm quote, in PCRS: {:?}", in_.PCRselect.pcrSelections);
        log::info!("tpm quote, out.quoted: {:?}", out_.quoted);
        log::info!("tpm quote, out.signature: {:?}", out_.signature.signature.ecdsa);

        return ret as usize;
    }
}

// Used to benchmark time to extend a PCR.
pub fn extend_pcr() -> usize {
    unsafe {
        let Some(ref mut dev) = DEV else {
            log::info!("TPM2 device not initialized");
            return usize::MAX;
        };

        let digest: [u8; 32] = [0; 32];
        let ret = wolfTPM2_ExtendPCR(dev, 23, TPM_ALG_SHA256.into(), digest.as_ptr(), 32);

        return ret as usize;
    }
}

// Run the TPM self test functionality
pub fn self_test() -> usize {
    unsafe {
        let Some(ref mut dev) = DEV else { return usize::MAX; };
        return wolfTPM2_SelfTest(dev) as usize;
    }
}

// Copy TPM signing key public bytes into a user-provided buffer
// Returns size of the key in bytes.
pub fn get_signing_key(public_key: &mut [u8]) -> usize {
    unsafe {
        let Some(ref mut signing_key) = SIGNING_KEY else {
            log::error!("signing_key not created");
            return 0;
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

// Sign a SHA256 digest directly
// Returns number of bytes copied into sig buffer, else -1 on error
pub fn sign(digest: &[u8], sig: &mut [u8]) -> i32 {
    let sigSz: &mut i32 = &mut (sig.len() as i32);
    let digestSz: &mut i32 = &mut (digest.len() as i32);

    unsafe {
        let Some(ref mut dev) = DEV else {
            log::error!("TPM2 device not initialized");
            return -1;
        };

        let Some(ref mut signing_key) = SIGNING_KEY else {
            log::error!("signing_key not created");
            return -1;
        };

        let ret: i32;
        if isECC(signing_key) {
            ret = wolfTPM2_SignHashScheme(dev, signing_key, digest.as_ptr(), *digestSz, sig.as_mut_ptr(), sigSz as *mut i32, TPM_ALG_ECDSA, TPM_ALG_SHA256);
        } else {
            ret = wolfTPM2_SignHashScheme(dev, signing_key, digest.as_ptr(), *digestSz, sig.as_mut_ptr(), sigSz as *mut i32, TPM_ALG_RSASSA, TPM_ALG_SHA256);
        }

        if (ret != 0) {
            log::error!("wolfTPM2_SignHashScheme failed with code {}", ret);
            return -1;
        }

        return *sigSz;
    }
}

// Sign a message, rather than providing the SHA256 digest
// Returns number of bytes copied into the sig buffer, else -1 on error
pub fn hash_and_sign(data: &[u8], sig: &mut [u8]) -> i32 {
    let hash = &mut WOLFTPM2_HASH::default();
    let digest = &mut [0; 32];
    let digestSz = &mut (digest.len() as u32);

    unsafe {
        let Some(ref mut dev) = DEV else {
            log::info!("TPM2 device not initialized");
            return -1;
        };

        let ret = wolfTPM2_HashStart(dev, hash, TPM_ALG_SHA256, ptr::null_mut(), 0);
        let ret = wolfTPM2_HashUpdate(dev, hash, data.as_ptr(), data.len().try_into().unwrap());
        let ret = wolfTPM2_HashFinish(dev, hash, digest.as_mut_ptr(), digestSz);

        return sign(digest, sig);
    }
}

/***********************************/
/** Extra misc. helpers and utils **/
/***********************************/

pub fn print_signing_key() {
    unsafe {
        let Some(ref mut signing_key) = SIGNING_KEY else {
            log::error!("signing_key not created");
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

// Was used for benchmarking TPM signing ops.
pub fn sign_e2e_benchmark(digest: &[u8], sig: &mut [u8]) -> u64 {
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