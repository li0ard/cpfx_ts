import { describe, test, expect } from "bun:test";
import { proceedCryptoProContainer } from "../src";

const pem256 = "-----BEGIN PRIVATE KEY-----\nMEYCAQAwHwYIKoUDBwEBAQEwEwYHKoUDAgIkAAYIKoUDBwEBAgIEIKbbEZ0Qh4s4\nUDfN/8LKlRoZjWBIXRSeKKP12jIJ+KlB\n-----END PRIVATE KEY-----";
const pem512 = "-----BEGIN PRIVATE KEY-----\nMGgCAQAwIQYIKoUDBwEBAQIwFQYJKoUDBwECAQIBBggqhQMHAQECAwRAfRGr/FOD\niHtCl0iCmumD6ITTneLxhmK7SIIdJaKLVNKVOO0kvFEzydkZs16vn6l+orbbssPT\nq9YWN2Pgp4tVmQ==\n-----END PRIVATE KEY-----";

describe("ckey", () => {
    test("256 bit", async () => {
        const headerKey = await Bun.file("tests/data/container_256/header.key").bytes();
        const masksKey = await Bun.file("tests/data/container_256/masks.key").bytes();
        const primaryKey = await Bun.file("tests/data/container_256/primary.key").bytes();
        const result = await proceedCryptoProContainer(headerKey, masksKey, primaryKey, "qawsqaws");

        expect(result.pem).toBe(pem256);
    }, 10000);

    test("512 bit", async () => {
        const headerKey = await Bun.file("tests/data/container_512/header.key").bytes();
        const masksKey = await Bun.file("tests/data/container_512/masks.key").bytes();
        const primaryKey = await Bun.file("tests/data/container_512/primary.key").bytes();
        const result = await proceedCryptoProContainer(headerKey, masksKey, primaryKey, "qawsqaws");

        expect(result.pem).toBe(pem512);
    }, 10000);
});