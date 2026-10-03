import { AsnProp, AsnPropTypes, BitString } from "@peculiar/asn1-schema";
import { AlgorithmIdentifier } from "@peculiar/asn1-x509";

export const id_gostpbe = "1.2.840.113549.1.12.1.80";
export const id_gost3410_12_256 = "1.2.643.7.1.1.1.1";
export const id_gost3410_12_512 = "1.2.643.7.1.1.1.2";
export const id_gost3410_agreement_512 = "1.2.643.7.1.1.6.2";

export class Gost3410Parameters {
    @AsnProp({ type: AsnPropTypes.ObjectIdentifier })
    curve = "";

    @AsnProp({ type: AsnPropTypes.ObjectIdentifier })
    digest = "";

    constructor(params: Partial<Gost3410Parameters> = {}) {
        Object.assign(this, params);
    }
}

export class PrivateKeyParameters {
    @AsnProp({ type: BitString })
    flags: BitString = new BitString();

    @AsnProp({ type: AlgorithmIdentifier, implicit: true, context: 0 })
    privateKeyParameters = new AlgorithmIdentifier();

    constructor(params: Partial<PrivateKeyParameters> = {}) {
        Object.assign(this, params);
    }
}