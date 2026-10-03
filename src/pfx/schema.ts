import { SafeBag } from "@peculiar/asn1-pfx";
import { AsnProp, AsnPropTypes } from "@peculiar/asn1-schema";
import { PrivateKeyParameters } from "../common.js";

export class PBEParameters {
    @AsnProp({ type: AsnPropTypes.OctetString })
    salt = new ArrayBuffer();

    @AsnProp({ type: AsnPropTypes.Integer })
    rounds = 0;

    constructor(params: Partial<PBEParameters> = {}) {
        Object.assign(this, params);
    }
}

export class KeyBag {
    @AsnProp({ type: SafeBag })
    value = new SafeBag();

    constructor(params: Partial<KeyBag> = {}) {
        Object.assign(this, params);
    }
}

export class ExportedKeyCek {
    @AsnProp({ type: AsnPropTypes.OctetString })
    enc = new ArrayBuffer();

    @AsnProp({ type: AsnPropTypes.OctetString })
    mac = new ArrayBuffer();

    constructor(params: Partial<ExportedKeyCek> = {}) {
        Object.assign(this, params);
    }
}

export class ExportedKeyValue {
    @AsnProp({ type: AsnPropTypes.OctetString })
    ukm = new ArrayBuffer();

    @AsnProp({ type: ExportedKeyCek })
    cek = new ExportedKeyCek();

    @AsnProp({ type: PrivateKeyParameters, implicit: true, context: 0 })
    keyParameters = new PrivateKeyParameters();

    constructor(params: Partial<ExportedKeyValue> = {}) {
        Object.assign(this, params);
    }
}

export class ExportedKey {
    @AsnProp({ type: ExportedKeyValue })
    value = new ExportedKeyValue();

    @AsnProp({ type: AsnPropTypes.OctetString })
    mac = new ArrayBuffer();

    constructor(params: Partial<ExportedKey> = {}) {
        Object.assign(this, params);
    }
}