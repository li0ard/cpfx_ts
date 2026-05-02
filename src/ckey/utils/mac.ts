import { mac_legacy, sboxes } from "@li0ard/magma"
import { derive } from "./cpkdf.js"
import type { TArg, TRet } from "@li0ard/gost3413";

/** Вычисление MAC контейнера */
export const computeContainerMAC = (
    data: TArg<Uint8Array>
): TRet<Uint8Array> => mac_legacy(
    new Uint8Array(32),
    data,
    new Uint8Array(8),
    sboxes.ID_TC26_GOST_28147_PARAM_Z
).slice(0, 4);

/** Вычисление MAC пароля */
export const computePasswordMAC = async (
    password: TArg<Uint8Array>,
    salt: TArg<Uint8Array>
): Promise<TRet<Uint8Array>> => mac_legacy(
    await derive(password, salt),
    new Uint8Array(16), 
    new Uint8Array(8),
    sboxes.ID_TC26_GOST_28147_PARAM_Z
).slice(0, 4);

/** Вычисление MAC маски и соли */
export const computeMaskMAC = (
    mask: TArg<Uint8Array>,
    salt: TArg<Uint8Array>
): TRet<Uint8Array> => mac_legacy(
    (mask.length == 32 ? mask : mask.slice(32)),
    salt,
    new Uint8Array(8),
    sboxes.ID_TC26_GOST_28147_PARAM_Z
).slice(0, 4);