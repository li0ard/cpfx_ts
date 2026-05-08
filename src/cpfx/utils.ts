import { gost341194 } from "@li0ard/gost341194";
import { concatBytes, hexToBytes, numberToBytesBE, type TArg, type TRet } from "@li0ard/gost3413";
import { decryptCFB, sboxes, unwrap } from "@li0ard/magma";
import { ExportKeyBlob, type ParsedBlob } from "./schema.js";
import { AsnConvert } from "@peculiar/asn1-schema";
import { PrivateKeyInfo } from "@peculiar/asn1-pkcs8";
import { kdf_gostr3411_2012_256 } from "@li0ard/streebog";

/** Преобразование строки в UTF-16le байты */
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
    let key = utf16le(pass);
    for(let i = 1; i < rounds + 1; i++)
        key = gost341194(concatBytes(key, salt, numberToBytesBE(i, 2)));

    return key;
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
): TRet<Uint8Array> => decryptCFB(
    key,
    encrypted,
    salt.slice(0, 8),
    true,
    sboxes.ID_GOST_28147_89_CRYPTO_PRO_A_PARAM_SET
);

/**
 * Парсинг экспортного представления ключа
 * 
 * Примечание:
 * MAC экспортного представления расчитывается следующим образом:
 * ```
 * M = MAC(KEKe, ExportKeyBlobValue)
 * ```
 * @param blob Ключевой блоб
 */
export const parseBlob = (blob: TArg<Uint8Array>): ParsedBlob => {
    const parsed = AsnConvert.parse(blob, PrivateKeyInfo);
    const cryptoproBlob = new Uint8Array(parsed.privateKey.buffer);
    const parsedBlob = AsnConvert.parse(cryptoproBlob.slice(16), ExportKeyBlob);

    return {
        exportEncoding: concatBytes(
            new Uint8Array(parsedBlob.value.ukm),
            new Uint8Array(parsedBlob.value.cek.enc),
            new Uint8Array(parsedBlob.value.cek.mac)
        ),
        oids: {
            algorithm: parsed.privateKeyAlgorithm.algorithm,
            curve: parsedBlob.value.parameters.privateKeyParameters.oids.curve,
            digest: parsedBlob.value.parameters.privateKeyParameters.oids.digest,
        }
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
 * @param key Ранее сгененрированный ключ
 * @param data Данные для unwrap алгоритма (`UKM || CEK_ENC || CEK_MAC`)
 */
export const decodeExport = (
    key: TArg<Uint8Array>,
    data: TArg<Uint8Array>
): TRet<Uint8Array> => {
    const KEKe = kdf_gostr3411_2012_256(key, hexToBytes("26BDB878"), data.slice(0, 8));
    return unwrap(KEKe, data);
}