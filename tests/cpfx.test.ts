import { describe, test, expect } from "bun:test";
import { proceed_pfx } from "../src";
import { EXPECTED_KEY256, EXPECTED_KEY512, EXPECTED_OIDS256, EXPECTED_OIDS512 } from "./data/results";


describe("cpfx", () => {
    test("256 bit", async () => {
        const file = await Bun.file("tests/data/256_qawsqaws.pfx").bytes();
        const result = await proceed_pfx(file, "qawsqaws");
        expect(result.privateKey).toStrictEqual(EXPECTED_KEY256);
        expect(result.oids).toStrictEqual(EXPECTED_OIDS256);
    }, 5000);

    test("512 bit", async () => {
        const file = await Bun.file("tests/data/512_qawsqaws.pfx").bytes();
        const result = await proceed_pfx(file, "qawsqaws");
        expect(result.privateKey).toStrictEqual(EXPECTED_KEY512);
        expect(result.oids).toStrictEqual(EXPECTED_OIDS512);
    }, 5000);
});