import type { TRet } from "@noble/hashes/utils.js";
import { PKCS8ShroudedKeyBag } from "@peculiar/asn1-pfx";
import { AsnProp, AsnPropTypes, BitString } from "@peculiar/asn1-schema";

export class PBEParameters {
    @AsnProp({ type: AsnPropTypes.OctetString })
    public salt: Uint8Array = new Uint8Array();

    @AsnProp({ type: AsnPropTypes.Integer })
    public rounds: number = 0;
}

export class ExportKeyBlobCek {
    @AsnProp({ type: AsnPropTypes.OctetString })
    public enc: Uint8Array = new Uint8Array();

    @AsnProp({ type: AsnPropTypes.OctetString })
    public mac: Uint8Array = new Uint8Array();
}

export class PrivateKeyOids {
    @AsnProp({ type: AsnPropTypes.ObjectIdentifier })
    public curve: string = "";

    @AsnProp({ type: AsnPropTypes.ObjectIdentifier })
    public digest: string = "";
}

export class PrivateKeyParameters {
    @AsnProp({ type: AsnPropTypes.ObjectIdentifier })
    public type: string = "";

    @AsnProp({ type: PrivateKeyOids, implicit: true })
    public oids: PrivateKeyOids = new PrivateKeyOids();
}


export class ExportKeyParameters {
    @AsnProp({ type: BitString })
    public flags: BitString = new BitString();

    @AsnProp({ type: PrivateKeyParameters, implicit: true })
    public privateKeyParameters: PrivateKeyParameters = new PrivateKeyParameters();
}

export class ExportKeyBlobValue {
    @AsnProp({ type: AsnPropTypes.OctetString })
    public ukm: Uint8Array = new Uint8Array();

    @AsnProp({ type: ExportKeyBlobCek })
    public cek: ExportKeyBlobCek = new ExportKeyBlobCek();

    @AsnProp({ type: ExportKeyParameters, implicit: true })
    public parameters: ExportKeyParameters = new ExportKeyParameters();
}

export class ExportKeyBlob {
    @AsnProp({ type: ExportKeyBlobValue })
    public value: ExportKeyBlobValue = new ExportKeyBlobValue();

    @AsnProp({ type: AsnPropTypes.OctetString })
    public mac: Uint8Array = new Uint8Array();
}

export class KeyBagValue {
    @AsnProp({ type: AsnPropTypes.ObjectIdentifier })
    public type: string = "";

    @AsnProp({ type: PKCS8ShroudedKeyBag, context: 0 })
    public value: PKCS8ShroudedKeyBag = new PKCS8ShroudedKeyBag();
}

export class KeyBag {
    @AsnProp({ type: KeyBagValue })
    public bagValue = new KeyBagValue();
}

export interface ExportOids {
    algorithm: string
    curve: string
    digest: string
}

export interface ParsedBlob {
    exportEncoding: TRet<Uint8Array>
    oids: ExportOids
}