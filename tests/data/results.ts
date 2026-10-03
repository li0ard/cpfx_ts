import { hexToBytes } from "@noble/hashes/utils.js";

export const EXPECTED_KEY256 = hexToBytes("a6db119d10878b385037cdffc2ca951a198d60485d149e28a3f5da3209f8a941");
export const EXPECTED_OIDS256 = {
    algorithm: "1.2.643.7.1.1.1.1",
    curve: "1.2.643.2.2.36.0",
    digest: "1.2.643.7.1.1.2.2"
}

export const EXPECTED_KEY512 = hexToBytes("7d11abfc5383887b429748829ae983e884d39de2f18662bb48821d25a28b54d29538ed24bc5133c9d919b35eaf9fa97ea2b6dbb2c3d3abd6163763e0a78b5599");
export const EXPECTED_OIDS512 = {
    algorithm: "1.2.643.7.1.1.1.2",
    curve: "1.2.643.7.1.2.1.2.1",
    digest: "1.2.643.7.1.1.2.3"
}