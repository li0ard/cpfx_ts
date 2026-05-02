export interface Result {
    ok: boolean;
    pem: string;
    err?: string;
}

export const err = (msg: string): Result => ({ ok: false, pem: "", err: msg });
export const ok = (pem: string): Result => ({ ok: true, pem });

export const id_gostpbe = "1.2.840.113549.1.12.1.80";
export const id_gost3410_12_256 = "1.2.643.7.1.1.1.1";
export const id_gost3410_12_512 = "1.2.643.7.1.1.1.2";
export const id_gost3410_agreement_512 = "1.2.643.7.1.1.6.2";