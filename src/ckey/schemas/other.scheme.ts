import { AsnProp, AsnPropTypes } from "@peculiar/asn1-schema";
import { computeMaskMAC } from "../utils/mac.js";
import { equalBytes } from "@noble/curves/utils.js";

/** Содержимое `name.key` */
export class ContainerName {
    @AsnProp({ type: AsnPropTypes.IA5String })
    name: string = "";
}

/** Содержимое `masks.key` и `masks2.key` */
export class ContainerMask {
    /** Маска для шифрования приватного ключа */
    @AsnProp({ type: AsnPropTypes.OctetString })
    mask!: ArrayBuffer;

    /** Соль для деривации пароля */
    @AsnProp({ type: AsnPropTypes.OctetString })
    salt!: ArrayBuffer;

    /** MAC маски и соли */
    @AsnProp({ type: AsnPropTypes.OctetString })
    mac!: ArrayBuffer;

    /** Проверка валидности MAC маски и соли */
    public isValidMAC(): boolean {
        return equalBytes(computeMaskMAC(
            new Uint8Array(this.mask),
            new Uint8Array(this.salt)
        ), new Uint8Array(this.mac));
    }
}

/** Содержимое `primary.key` и `primary2.key` */
export class ContainerPrimary {
    @AsnProp({ type: AsnPropTypes.OctetString })
    /** Зашифрованный приватный ключ */
    value: Uint8Array = new Uint8Array();
}