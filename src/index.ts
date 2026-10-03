import { AlgorithmIdentifier } from "@peculiar/asn1-x509";
import { base64, type TArg, type TRet } from "@scure/base";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { PrivateKeyInfo } from "@peculiar/asn1-pkcs8";
import { Gost3410Parameters } from "./common.js";

export type ExportOids = {
    algorithm: string;
    curve: string;
    digest: string;
}

export type ExportedPrivateKey = {
    privateKey: TRet<Uint8Array>;
    oids: ExportOids;
}

const pem = (data: TArg<Uint8Array>, header: string): string => `-----BEGIN ${header.toUpperCase()}-----\n${base64.encode(data).replace(/(.{64})/g, "$1\n")}\n-----END ${header.toUpperCase()}-----`;

export const encodePrivateKeyToPem = (
    exported: ExportedPrivateKey
): string => pem(new Uint8Array(AsnConvert.serialize(
    new PrivateKeyInfo({
        privateKeyAlgorithm: new AlgorithmIdentifier({
            algorithm: exported.oids.algorithm,
            parameters: AsnConvert.serialize(new Gost3410Parameters({ ...exported.oids }))
        }),
        privateKey: new OctetString(exported.privateKey.buffer)
    })
)), "PRIVATE KEY");

export * from "./cryptopro/index.js";
export * from "./pfx/index.js";