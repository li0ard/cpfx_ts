import { cfb, gost341194, kdf_gostr3411_2012_256, kwp, mac_legacy, Magma, magmaSboxes } from "@li0ard/gost";
import { concatBytes, equalBytes, hexToBytes, numberToBytesBE, type TArg, type TRet } from "@noble/curves/utils.js";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { PrivateKeyInfo } from "@peculiar/asn1-pkcs8";
import { ExportedKey } from "./schema.js";
import type { ExportedPrivateKey } from "../index.js";
import { Gost3410Parameters, id_gost3410_12_256, id_gost3410_12_512 } from "../common.js";

export const KEYWRAP_LABEL = hexToBytes("26BDB878");

export const parseEncapsulatedOctetString = (
    data: TArg<Uint8Array> | TArg<ArrayBuffer>
): TRet<Uint8Array> => new Uint8Array(AsnConvert.parse(data, OctetString).buffer);

const utf16le = (str: string): TRet<Uint8Array> => {
    const buffer = new Uint8Array(str.length * 2);
    for (let i = 0; i < str.length; i++) {
        const code = str.charCodeAt(i);
        buffer[i * 2] = code & 0xFF;
        buffer[i * 2 + 1] = (code >> 8) & 0xFF;
    }
    return buffer;
}

/**
 * Подготовка ключа для снятия транспортного шифрования
 * ```
 * K0 = utf16(PASS)
 * 
 * ∀i ∊ {1,2,...,r}: K_i = GOST341194(K_i-1 || salt || i)
 * ```
 * @param pass Пароль от PFX
 * @param salt Вектор инициализации (Прописан в PFX)
 * @param rounds Количество итераций хэширования (Прописано в PFX)
 */
export const prepareTransportKey = async (
    pass: string,
    salt: TArg<Uint8Array>,
    rounds: number
): Promise<TRet<Uint8Array>> => {
    const hasher = gost341194.create();
    const out = hasher.update(utf16le(pass)).update(salt).update(numberToBytesBE(1, 2)).digest();
    for (let i = 2; i <= rounds; i++)
        hasher.update(out).update(salt).update(numberToBytesBE(i, 2)).digestInto(out);

    return out;
}

/**
 * Снятие транспортного шифрования
 * @param key Ранее сгененрированный ключ (через {@link prepareTransportKey})
 * @param salt Вектор инициализации (Прописан в PFX)
 * @param encrypted Зашифрованный ключевой блоб
 * 
 * ```
 * gost2814789_cfb(key, encrypted, salt, CRYPTO_PRO_A_PARAM_SET)
 * ```
 */
export const decodeTransport = (
    key: TArg<Uint8Array>,
    salt: TArg<Uint8Array>,
    encrypted: TArg<Uint8Array>
): TRet<Uint8Array> => cfb(
    new Magma(key, magmaSboxes.ID_GOST_28147_89_CRYPTO_PRO_A_PARAM_SET, true),
    salt.subarray(0,8)
).decrypt(encrypted);

/**
 * Парсинг экспортного представления ключа
 * 
 * Примечание:
 * MAC экспортного представления расчитывается следующим образом:
 * ```
 * M = MAC(KEKe, ExportedKeyValue)
 * ```
 * @param blob Ключевой блоб
 */
export const parseBlob = (blob: TArg<Uint8Array>) => {
    const pki = AsnConvert.parse(blob, PrivateKeyInfo);
    const parsedBlob = AsnConvert.parse(
        new Uint8Array(pki.privateKey.buffer).subarray(16), // Пропускаем блоб КриптоПро
        ExportedKey
    );

    const keyOids = AsnConvert.parse(parsedBlob.value.keyParameters.privateKeyParameters.parameters!, Gost3410Parameters)

    return {
        // Формат для key wrap Магмы: UKM || CEK_ENC || CEK_MAC
        exportEncoding: concatBytes(
            new Uint8Array(parsedBlob.value.ukm),
            new Uint8Array(parsedBlob.value.cek.enc),
            new Uint8Array(parsedBlob.value.cek.mac)
        ), 
        oids: {
            algorithm: pki.privateKeyAlgorithm.algorithm,
            curve: keyOids.curve,
            digest: keyOids.digest
        },
        macPayload: new Uint8Array(AsnConvert.serialize(parsedBlob.value)),
        mac: new Uint8Array(parsedBlob.mac)
    }
}

/**
 * Снятие экспортного шифрования
 * ```
 * label = 0x26BDB878
 * 
 * KEKe = KDF_GOSTR3411_2012_256(K, label, UKM)
 * Ks = unwrap(KEKe, (UKM || CEK_ENC || CEK_MAC))
 * ```
 */
export const decodeExport = (
    transportKey: TArg<Uint8Array>,
    exportKeyStruct: TArg<Uint8Array>
): ExportedPrivateKey => {
    const blob = parseBlob(exportKeyStruct);
    if(blob.oids.algorithm !== id_gost3410_12_256 && blob.oids.algorithm !== id_gost3410_12_512)
        throw new Error("Only GOST 34.10-2012 supported");

    const exportKey = kdf_gostr3411_2012_256(
        transportKey,
        KEYWRAP_LABEL,
        blob.exportEncoding.subarray(0, 8)
    );
    const macActual = mac_legacy(new Magma(
        exportKey,
        magmaSboxes.ID_GOST_28147_89_CRYPTO_PRO_A_PARAM_SET,
        true
    )).compute(blob.macPayload).subarray(0,4);
    if(!equalBytes(macActual, blob.mac))
        throw new Error("Invalid MAC of export key structure");

    const privateKey = kwp(exportKey).unwrap(blob.exportEncoding);
    return { privateKey, oids: blob.oids }
}