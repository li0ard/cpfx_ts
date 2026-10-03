import { AsnConvert } from "@peculiar/asn1-schema";
import { bytesToNumberLE, equalBytes, type TArg, type TRet } from "@noble/curves/utils.js";
import { Container, ContainerMask, ContainerPrimary } from "./schema.js";
import { cpkdf, ecb, getCurveByOid, Magma, magmaSboxes } from "@li0ard/gost";
import { Gost3410Parameters, id_gost3410_12_256, id_gost3410_12_512, id_gost3410_agreement_512 } from "../common.js";
import type { ExportedPrivateKey } from "../index.js";

export const proceed_cryptopro = async (
    headerKey: TArg<Uint8Array>,
    masksKey: TArg<Uint8Array>,
    primaryKey: TArg<Uint8Array>,
    passw: string
): Promise<ExportedPrivateKey> => {
    try {
        const container = AsnConvert.parse(headerKey, Container);
        const masks = AsnConvert.parse(masksKey, ContainerMask);
        const primary = AsnConvert.parse(primaryKey, ContainerPrimary);

        if(!(await container.verifyPassword(passw))) throw new Error("Invalid password");
        if(!container.isValidMAC()) throw new Error("Invalid container MAC");
        if(!masks.isValidMAC()) throw new Error("Invalid masks MAC");

        const gost3410Paramters = AsnConvert.parse(
            container.content.primaryKeyParameters.privateKeyParameters.parameters!,
            Gost3410Parameters
        );

        const signer = getCurveByOid(gost3410Paramters.curve);
        if(!signer) throw new Error("Invalid curve");
        const curveLength = signer.Point.Fp.BYTES;

        const maskedPrivateKey = bytesToNumberLE(ecb(new Magma(
            cpkdf(passw, new Uint8Array(masks.salt)),
            magmaSboxes.ID_TC26_GOST_28147_PARAM_Z,
            true
        )).decrypt(new Uint8Array(primary.value)));

        const mask = bytesToNumberLE(new Uint8Array(masks.mask));
        const privateKey = signer.Point.Fn.toBytes(
            signer.Point.Fn.div(maskedPrivateKey, mask)
        ) as TRet<Uint8Array>;

        if(container.content.primaryFP) {
            if(!equalBytes(
                signer.getPublicKey(privateKey, false).slice(curveLength - 7, curveLength + 1).reverse(),
                new Uint8Array(container.content.primaryFP)
            )) throw new Error("Public key verification error");
        }

        return {
            privateKey: privateKey.reverse(),
            oids: {
                algorithm: container.content.primaryKeyParameters.privateKeyParameters.algorithm == id_gost3410_agreement_512
                    ? id_gost3410_12_512
                    : id_gost3410_12_256,
                ...gost3410Paramters
            }
        }
    } catch(e) {
        console.error(e)
        throw new Error("Containter decoding error. Perhaps just incorrect password");
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