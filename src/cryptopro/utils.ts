import { cpkdf, mac_legacy, Magma, magmaSboxes } from "@li0ard/gost";
import type { TArg, TRet } from "@noble/curves/utils.js";
import type { KDFInput } from "@noble/hashes/utils.js";

/** Вычисление MAC маски */
export const computeMaskMAC = (
    mask: TArg<Uint8Array>,
    salt: TArg<Uint8Array>
): TRet<Uint8Array> => mac_legacy(new Magma(
    mask.length == 32 ? mask : mask.slice(32),
    magmaSboxes.ID_TC26_GOST_28147_PARAM_Z,
    true
)).compute(salt).slice(0,4);

/** Вычисление MAC контейнера */
export const computeContainerMAC = (
    data: TArg<Uint8Array>
): TRet<Uint8Array> => mac_legacy(new Magma(
    new Uint8Array(32),
    magmaSboxes.ID_TC26_GOST_28147_PARAM_Z,
    true
)).compute(data).slice(0, 4);

/** Вычисление MAC пароля */
export const computePasswordMAC = async (
    password: TArg<KDFInput>,
    salt: TArg<KDFInput>
): Promise<TRet<Uint8Array>> => mac_legacy(new Magma(
    cpkdf(password, salt),
    magmaSboxes.ID_TC26_GOST_28147_PARAM_Z,
    true
)).compute(new Uint8Array(16)).slice(0,4);