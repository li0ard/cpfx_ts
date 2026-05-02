import { describe, test, expect } from "bun:test";
import { proceedPFX } from "../src";

const pem256 = "-----BEGIN PRIVATE KEY-----\nMEYCAQAwHwYIKoUDBwEBAQEwEwYHKoUDAgIkAAYIKoUDBwEBAgIEIKbbEZ0Qh4s4\nUDfN/8LKlRoZjWBIXRSeKKP12jIJ+KlB\n-----END PRIVATE KEY-----";
const pem512 = "-----BEGIN PRIVATE KEY-----\nMGgCAQAwIQYIKoUDBwEBAQIwFQYJKoUDBwECAQIBBggqhQMHAQECAwRAfRGr/FOD\niHtCl0iCmumD6ITTneLxhmK7SIIdJaKLVNKVOO0kvFEzydkZs16vn6l+orbbssPT\nq9YWN2Pgp4tVmQ==\n-----END PRIVATE KEY-----";

describe("cpfx", () => {
    test("256 bit", async () => {
        const file = await Bun.file("tests/data/256_qawsqaws.pfx").bytes();
        const result = await proceedPFX(file, "qawsqaws");
        expect(result.ok).toBeTrue();
        expect(result.pem).toBe(pem256);
    }, 5000);

    test("512 bit", async () => {
        const file = await Bun.file("tests/data/512_qawsqaws.pfx").bytes();
        const result = await proceedPFX(file, "qawsqaws");
        expect(result.ok).toBeTrue();
        expect(result.pem).toBe(pem512);
    }, 5000);
});