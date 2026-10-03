import { describe, test, expect } from "bun:test";
import { proceed_cryptopro } from "../src";
import { EXPECTED_KEY256, EXPECTED_KEY512, EXPECTED_OIDS256, EXPECTED_OIDS512 } from "./data/results";

describe("ckey", () => {
    test("256 bit", async () => {
        const headerKey = await Bun.file("tests/data/container_256/header.key").bytes();
        const masksKey = await Bun.file("tests/data/container_256/masks.key").bytes();
        const primaryKey = await Bun.file("tests/data/container_256/primary.key").bytes();
        const result = await proceed_cryptopro(headerKey, masksKey, primaryKey, "qawsqaws");

        expect(result.privateKey).toStrictEqual(EXPECTED_KEY256);
        expect(result.oids).toStrictEqual(EXPECTED_OIDS256);
    }, 10000);

    test("512 bit", async () => {
        const headerKey = await Bun.file("tests/data/container_512/header.key").bytes();
        const masksKey = await Bun.file("tests/data/container_512/masks.key").bytes();
        const primaryKey = await Bun.file("tests/data/container_512/primary.key").bytes();
        const result = await proceed_cryptopro(headerKey, masksKey, primaryKey, "qawsqaws");

        expect(result.privateKey).toStrictEqual(EXPECTED_KEY512);
        expect(result.oids).toStrictEqual(EXPECTED_OIDS512);
    }, 10000);
});