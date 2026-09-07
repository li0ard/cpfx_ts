import type { TArg, TRet } from "@noble/hashes/utils.js";
import { mac_legacy as mac_legacy_ } from "@li0ard/gost/modes.js";
import { Magma, magmaSboxes } from "@li0ard/gost/magma.js";
import { cpkdf } from "@li0ard/gost/kdf.js";

/** Вычисление MAC контейнера */
export const computeContainerMAC = (
    data: TArg<Uint8Array>
): TRet<Uint8Array> => mac_legacy_(
    new Magma(new Uint8Array(32), magmaSboxes.ID_TC26_GOST_28147_PARAM_Z, true),
    new Uint8Array(8)
).compute(data).slice(0, 4);

/** Вычисление MAC пароля */
export const computePasswordMAC = async (
    password: TArg<Uint8Array>,
    salt: TArg<Uint8Array>
): Promise<TRet<Uint8Array>> => mac_legacy_(
    new Magma(cpkdf(password, salt), magmaSboxes.ID_TC26_GOST_28147_PARAM_Z, true),
    new Uint8Array(8)
).compute(new Uint8Array(16)).slice(0,4);

/** Вычисление MAC маски и соли */
export const computeMaskMAC = (
    mask: TArg<Uint8Array>,
    salt: TArg<Uint8Array>
): TRet<Uint8Array> => mac_legacy_(
    new Magma((mask.length == 32 ? mask : mask.slice(32)), magmaSboxes.ID_TC26_GOST_28147_PARAM_Z, true),
    new Uint8Array(8)
).compute(salt).slice(0,4);