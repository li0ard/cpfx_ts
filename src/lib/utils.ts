import type { TArg } from "@noble/hashes/utils.js";
import { base64 } from "@scure/base";
import { PrivateKeyOids, type ExportOids } from "../cpfx/schema.js";
import { AsnConvert, OctetString } from "@peculiar/asn1-schema";
import { AlgorithmIdentifier } from "@peculiar/asn1-x509";
import { PrivateKeyInfo } from "@peculiar/asn1-pkcs8";

const pem = (data: TArg<Uint8Array>, header: string): string => (
    `-----BEGIN ${header.toUpperCase()}-----\n${base64.encode(data).replace(/(.{64})/g, "$1\n")}\n-----END ${header.toUpperCase()}-----`
);

export const ks2pem = (ks: TArg<Uint8Array>, oids: ExportOids): string => {
    const encodedOids = new PrivateKeyOids();
    encodedOids.curve = oids.curve;
    encodedOids.digest = oids.digest;

    const algorithmIdentifier = new AlgorithmIdentifier();
    algorithmIdentifier.algorithm = oids.algorithm;
    algorithmIdentifier.parameters = AsnConvert.serialize(encodedOids);

    const ksAsOctetString = new OctetString(ks.buffer);

    const privateKeyInfo = new PrivateKeyInfo();
    privateKeyInfo.privateKeyAlgorithm = algorithmIdentifier;
    privateKeyInfo.privateKey = ksAsOctetString;

    return pem(new Uint8Array(AsnConvert.serialize(privateKeyInfo)), "PRIVATE KEY");
}