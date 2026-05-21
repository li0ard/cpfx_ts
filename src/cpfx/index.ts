import type { TArg } from "@noble/hashes/utils.js";
import { id_data } from "@peculiar/asn1-cms";
import { PFX, SafeContents } from "@peculiar/asn1-pfx";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { KeyBag, PBEParameters } from "./schema.js";
import { decodeExport, decodeTransport, parseBlob, prepareTransportKey } from "./utils.js";
import { ks2pem } from "../lib/utils.js";
import { err, id_gost3410_12_256, id_gost3410_12_512, id_gostpbe, ok, type Result } from "../lib/const.js";

/**
 * Декодирование файла .pfx экспортированного из КриптоПро
 * @param file Содержимое файла .pfx
 * @param passw Пароль от файла
 */
export const proceedPFX = async (
    file: TArg<Uint8Array>,
    passw: string
): Promise<Result> => {
    // Шаг 1. Декодируем PFX и фильтруем keybag'и
    const pfx = AsnConvert.parse(file, PFX);
    if (pfx.version != 3)
        throw new Error("can only decode v3 PFX PDU");
    if (pfx.authSafe.contentType !== id_data)
        throw new Error("only password-protected PFX is implemented");

    const data = new Uint8Array(AsnConvert.parse(pfx.authSafe.content, OctetString).buffer);
    const bags = AsnConvert.parse(data, SafeContents).find(i => i.bagId == id_data)
    if(!bags) throw new Error("Missing private key");

    const keyBag = AsnConvert.parse(
        AsnConvert.parse(bags.bagValue, OctetString).buffer, KeyBag
    ).bagValue.value;
    if(keyBag.encryptionAlgorithm.algorithm !== id_gostpbe)
        throw new Error("Invalid key bag: Not GOST PBE");

    // Шаг 2. Получаем параметры PBE и снимаем транспортное шифрование
    const parameters = AsnConvert.parse(keyBag.encryptionAlgorithm.parameters!, PBEParameters);
    const transportKey = await prepareTransportKey(passw, new Uint8Array(parameters.salt), parameters.rounds);
    try {
        const decodedTransport = decodeTransport(
            transportKey,
            new Uint8Array(parameters.salt),
            new Uint8Array(keyBag.encryptedData.buffer)
        );
        // Шаг 3. Парсим ключевой и экспортное представление приватного ключа
        const blob = parseBlob(decodedTransport);
        if(blob.oids.algorithm !== id_gost3410_12_256 && blob.oids.algorithm !== id_gost3410_12_512)
            return err("Only GOST 34.10-2012 supported");

        // Шаг 4. Снятие экспортного шифрования
        const Ks = decodeExport(transportKey, blob.exportEncoding);
        return ok(ks2pem(Ks, blob.oids));
    } catch(e) {
        console.error(e);
        return err("Blob decoding error. Perhaps just incorrect password");
    }
}