import type { TArg, TRet } from "@li0ard/gost3413";
import { err, ok, type Result } from "../lib/const.js";
import { AsnConvert } from "@peculiar/asn1-schema";
import { Container } from "./schemas/main.scheme.js";
import { ContainerMask, ContainerPrimary } from "./schemas/other.scheme.js";
import { ks2pem } from "../lib/utils.js";

/**
 * Декодирование контейнера КриптоПро
 * @param headerKey Содержимое файла header.key
 * @param masksKey Содержимое файла masks.key
 * @param primaryKey Содержимое файла primary.key
 * @param passw Пароль от контейнера
 */
export const proceedCryptoProContainer = async (
    headerKey: TArg<Uint8Array>,
    masksKey: TArg<Uint8Array>,
    primaryKey: TArg<Uint8Array>,
    passw: string
): Promise<Result> => {
    try {
        const container = AsnConvert.parse(headerKey, Container);
        const masks = AsnConvert.parse(masksKey, ContainerMask);
        const primary = AsnConvert.parse(primaryKey, ContainerPrimary);

        if(!(await container.verifyPassword(passw)))
            console.warn("Неудачная проверка пароля. Экспорт будет произведён, но точность не гарантируется");
        const key = await container.getPrivateKey(passw, primary.value, masks);

        return ok(ks2pem(key, container.getAlgorithm()))
    } catch(e) {
        console.error(e)
        return err(e as string);
    }
}

/**
 * Изменение флага экспортируемости контейнера
 * @param headerKey Содержимое файла header.key
 * @param exportable Новое значение флага экспортируемости
 */
export const changeContainerExportable = (
    headerKey: TArg<Uint8Array>,
    exportable: boolean
): TRet<Uint8Array> => {
    const container = AsnConvert.parse(headerKey, Container);
    container.setExportable(exportable);

    return new Uint8Array(AsnConvert.serialize(container));
}