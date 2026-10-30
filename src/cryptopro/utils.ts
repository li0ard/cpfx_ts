import { cpkdf, mac_legacy, MagmaLegacy, magmaSboxes } from "@li0ard/gost";
import type { TArg, TRet } from "@noble/curves/utils.js";
import type { KDFInput } from "@noble/hashes/utils.js";

/** Вычисление MAC маски */
export const computeMaskMAC = (
    mask: TArg<Uint8Array>,
    salt: TArg<Uint8Array>
): TRet<Uint8Array> => mac_legacy(new MagmaLegacy(
    mask.length == 32 ? mask : mask.slice(32),
    magmaSboxes.TC26_GOST_28147_PARAM_Z
)).compute(salt).slice(0,4);

/** Вычисление MAC контейнера */
export const computeContainerMAC = (
    data: TArg<Uint8Array>
): TRet<Uint8Array> => mac_legacy(new MagmaLegacy(
    new Uint8Array(32),
    magmaSboxes.TC26_GOST_28147_PARAM_Z
)).compute(data).slice(0, 4);

/** Вычисление MAC пароля */
export const computePasswordMAC = async (
    password: TArg<KDFInput>,
    salt: TArg<KDFInput>
): Promise<TRet<Uint8Array>> => mac_legacy(new MagmaLegacy(
    cpkdf(password, salt),
    magmaSboxes.TC26_GOST_28147_PARAM_Z
)).compute(new Uint8Array(16)).slice(0,4);