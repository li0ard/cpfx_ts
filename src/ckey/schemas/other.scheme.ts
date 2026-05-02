import { equalBytes } from "@li0ard/gost3413";
import { AsnProp, AsnPropTypes } from "@peculiar/asn1-schema";
import { computeMaskMAC } from "../utils/mac.js";

/** Содержимое `name.key` */
export class ContainerName {
    @AsnProp({ type: AsnPropTypes.IA5String })
    name: string = "";
}

/** Содержимое `masks.key` и `masks2.key` */
export class ContainerMask {
    /** Маска для шифрования приватного ключа */
    @AsnProp({ type: AsnPropTypes.OctetString })
    mask: Uint8Array = new Uint8Array();

    /** Соль для деривации пароля */
    @AsnProp({ type: AsnPropTypes.OctetString })
    salt: Uint8Array = new Uint8Array();

    /** MAC маски и соли */
    @AsnProp({ type: AsnPropTypes.OctetString })
    mac: Uint8Array = new Uint8Array();

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