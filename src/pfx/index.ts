import type { TArg } from "@noble/hashes/utils.js";
import { id_data } from "@peculiar/asn1-cms";
import { AuthenticatedSafe, id_pkcs8ShroudedKeyBag, PFX, PKCS8ShroudedKeyBag, SafeContents } from "@peculiar/asn1-pfx";
import { AsnConvert } from "@peculiar/asn1-schema";
import { decodeExport, decodeTransport, parseEncapsulatedOctetString, prepareTransportKey } from "./utils.js";
import { PBEParameters } from "./schema.js";
import type { ExportedPrivateKey } from "../index.js";
import { id_gostpbe } from "../common.js";

/**
 * Экспорт приватного ключа из PKCS#12
 * @param file Файл PKCS#12
 * @param password Пароль
 */
export const proceed_pfx = async (
    file: TArg<Uint8Array>,
    password: string
): Promise<ExportedPrivateKey> => {
    const pfx = AsnConvert.parse(file, PFX);
    if (pfx.version != 3)
        throw new Error("can only decode v3 PFX PDU");
    if (pfx.authSafe.contentType !== id_data)
        throw new Error("only password-protected PFX is implemented");

    const authSafe = AsnConvert.parse(
        parseEncapsulatedOctetString(pfx.authSafe.content),
        AuthenticatedSafe
    );

    let keyBag: PKCS8ShroudedKeyBag | undefined;
    for(const ci of authSafe) {
        if (ci.contentType !== id_data) continue;
        const safeContents = AsnConvert.parse(
            parseEncapsulatedOctetString(ci.content),
            SafeContents
        );
        const safeBag = safeContents.find(b => b.bagId === id_pkcs8ShroudedKeyBag);
        if (safeBag) {
            keyBag = AsnConvert.parse(safeBag.bagValue, PKCS8ShroudedKeyBag);
            break;
        }
    }
    if(!keyBag) throw new Error("Missing private key bag");
    if(keyBag.encryptionAlgorithm.algorithm !== id_gostpbe)
        throw new Error("Invalid key bag: Not GOST PBE");

    const parameters = AsnConvert.parse(
        keyBag.encryptionAlgorithm.parameters!,
        PBEParameters
    );
    
    const transportSalt = new Uint8Array(parameters.salt);
    const transportKey = await prepareTransportKey(password, transportSalt, parameters.rounds);
    try {
        const pki = decodeTransport(
            transportKey,
            transportSalt,
            new Uint8Array(keyBag.encryptedData.buffer)
        );
        
        return decodeExport(transportKey, pki);
    } catch(e) {
        console.error(e);
        throw new Error("Blob decoding error. Perhaps just incorrect password");
    }
}

console.log(await proceed_pfx(
    await Bun.file("tests/data/256_qawsqaws.pfx").bytes(),
    "qawsqaws"
))