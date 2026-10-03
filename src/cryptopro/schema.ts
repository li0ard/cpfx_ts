import { AsnConvert, AsnProp, AsnPropTypes, BitString } from "@peculiar/asn1-schema";
import { computeContainerMAC, computeMaskMAC, computePasswordMAC } from "./utils.js";
import { equalBytes } from "@noble/curves/utils.js";
import { PrivateKeyParameters } from "../common.js";
import { Extensions } from "@peculiar/asn1-x509";

/** Содержимое `name.key` */
export class ContainerName {
    @AsnProp({ type: AsnPropTypes.IA5String })
    name: string = "";

    constructor(params: Partial<ContainerName> = {}) {
        Object.assign(this, params);
    }
}

/** Содержимое `masks.key` и `masks2.key` */
export class ContainerMask {
    /** Маска для шифрования приватного ключа */
    @AsnProp({ type: AsnPropTypes.OctetString })
    mask = new ArrayBuffer();

    /** Соль для деривации пароля */
    @AsnProp({ type: AsnPropTypes.OctetString })
    salt = new ArrayBuffer();

    /** MAC маски и соли */
    @AsnProp({ type: AsnPropTypes.OctetString })
    mac = new ArrayBuffer();

    /** Проверка валидности MAC маски и соли */
    isValidMAC(): boolean {
        return equalBytes(computeMaskMAC(
            new Uint8Array(this.mask),
            new Uint8Array(this.salt)
        ), new Uint8Array(this.mac));
    }

    constructor(params: Partial<ContainerMask> = {}) {
        Object.assign(this, params);
    }
}

/** Содержимое `primary.key` и `primary2.key` */
export class ContainerPrimary {
    @AsnProp({ type: AsnPropTypes.OctetString })
    /** Зашифрованный приватный ключ */
    value = new ArrayBuffer();

    constructor(params: Partial<ContainerPrimary> = {}) {
        Object.assign(this, params);
    }
}

export class CertificateLink {
    @AsnProp({ type: AsnPropTypes.IA5String })
    path = "";

    @AsnProp({ type: AsnPropTypes.OctetString })
    hmac = new ArrayBuffer();

    constructor(params: Partial<CertificateLink> = {}) {
        Object.assign(this, params);
    }
}

export class ContainerContent {
    @AsnProp({ type: AsnPropTypes.ObjectIdentifier, context: 0, optional: true })
    algorithmIdentifier = "";

    @AsnProp({ type: AsnPropTypes.IA5String, optional: true })
    containerName?: string;

    @AsnProp({ type: BitString })
    attributes = new BitString();

    @AsnProp({ type: PrivateKeyParameters })
    primaryKeyParameters = new PrivateKeyParameters();

    @AsnProp({ type: AsnPropTypes.OctetString, context: 2, implicit: true, optional: true })
    hmacPassword?: ArrayBuffer;

    @AsnProp({ type: AsnPropTypes.Any, context: 3, optional: true })
    secondaryEncryptedKey?: ArrayBuffer;

    @AsnProp({ type: PrivateKeyParameters, context: 4, implicit: true, optional: true })
    secondaryKeyParameters?: PrivateKeyParameters;

    @AsnProp({ type: AsnPropTypes.OctetString, context: 5,  implicit: true, optional: true })
    primaryCertificate?: ArrayBuffer;

    @AsnProp({ type: AsnPropTypes.OctetString, context: 6, implicit: true, optional: true })
    secondaryCertificate?: ArrayBuffer;

    @AsnProp({ type: AsnPropTypes.IA5String, context: 7, implicit: true, optional: true })
    encryptionContainerName?: string;

    @AsnProp({ type: CertificateLink, context: 8, implicit: true, optional: true })
    primaryCertificateLink?: CertificateLink;

    @AsnProp({ type: CertificateLink, context: 9, implicit: true, optional: true })
    secondaryCertificateLink?: CertificateLink;

    @AsnProp({ type: AsnPropTypes.OctetString, context: 10, implicit: true, optional: true })
    primaryFP?: ArrayBuffer;

    @AsnProp({ type: AsnPropTypes.OctetString, context: 11, implicit: true, optional: true })
    secondaryFP?: ArrayBuffer;

    @AsnProp({ type: AsnPropTypes.ObjectIdentifier, optional: true })
    passwordPolicy?: string;

    @AsnProp({ type: AsnPropTypes.Integer, optional: true })
    containerSecurityLevel?: number;

    @AsnProp({ type: Extensions, context: 12, implicit: true, optional: true })
    extensions?: Extensions;

    @AsnProp({ type: AsnPropTypes.IA5String, context: 13, implicit: true, optional: true })
    secondaryContainerName?: string;

    constructor(params: Partial<ContainerContent> = {}) {
        Object.assign(this, params);
    }
}

/** Содержимое `header.key` */
export class Container {
    /** Содержимое контейнера */
    @AsnProp({ type: ContainerContent })
    content = new ContainerContent();

    /** MAC контейнера */
    @AsnProp({ type: AsnPropTypes.OctetString })
    mac = new ArrayBuffer();

    constructor(params: Partial<Container> = {}) {
        Object.assign(this, params);
    }

    isValidMAC(): boolean {
        return equalBytes(
            computeContainerMAC(new Uint8Array(AsnConvert.serialize(this.content))),
            new Uint8Array(this.mac)
        );
    }

    public async verifyPassword(passw: string): Promise<boolean> {
        if(!this.content.primaryFP) throw new Error("Missing Primary FP");
        if(!this.content.hmacPassword) throw new Error("Missing password HMAC");
        return equalBytes(
            await computePasswordMAC(
                passw, 
                new Uint8Array(this.content.primaryFP)
            ),
            new Uint8Array(this.content.hmacPassword)
        );
    }

    setExportable(exportable: boolean) {
        const bitString = this.content.primaryKeyParameters.flags;
        const arr = new Uint8Array(bitString.value);

        if (arr.length === 0) return;

        const mask = 0b10000000;

        if (exportable) arr[0] |= mask;
        else arr[0] &= ~mask;

        bitString.value = arr.buffer;
        this.content.primaryKeyParameters.flags = bitString;
        this.mac = computeContainerMAC(new Uint8Array(AsnConvert.serialize(this.content))).buffer;
    }
}