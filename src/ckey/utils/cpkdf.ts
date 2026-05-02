import { pad1, xor, type TArg, type TRet } from "@li0ard/gost3413";
import { Streebog256 } from "@li0ard/streebog";

/** CryptoPro Key Derivation Function (CPKDF) */
export const derive = async (
    passphrase: TArg<Uint8Array>,
    salt: TArg<Uint8Array>
): Promise<TRet<Uint8Array>> => {
    let hasher = Streebog256.create()
    const bs = hasher.outputLen * 2
    if(passphrase.length * 4 > 1024) throw new Error("passphrase cannot be longer than 256 symbols");

    // Делаем пароль в 4 раза больше
    const pin = new Uint8Array(passphrase.length * 4);
    for(let i = 0; i < passphrase.length; i++) pin[i*4] = passphrase[i]!;
    
    // Шаг 1. получаем хэш соли и пароля (если задан)
    hasher.update(salt);
    if(passphrase.length != 0) hasher.update(pin);
    const hash = hasher.digest();
    hasher = Streebog256.create();

    // Создание основого и вторичных массивов
    let c = pad1(new TextEncoder().encode("DENEFH028.760246785.IUEFHWUIO.EF"), bs);
    let m0 = new Uint8Array(64);
    let m1 = new Uint8Array(64);

    // Устанавливаем количество итераций
    let iterations = 2;
    if(passphrase.length != 0) iterations = 2000;

    // Шаг 2. Мульти-итеративное хэширование
    for(let j = 0; j < iterations; j++) {
        m0 = xor(c, new Uint8Array(c.length).fill(0x36));
        m1 = xor(c, new Uint8Array(c.length).fill(0x5C));

        hasher.update(m0);
        hasher.update(hash);
        hasher.update(m1);
        hasher.update(hash);

        c = pad1(hasher.digest(), bs);
        hasher = Streebog256.create();
    }

    // Шаг 3. Получаем хэш соли и вторичных массивов
    m0 = xor(c, new Uint8Array(c.length).fill(0x36));
    m1 = xor(c, new Uint8Array(c.length).fill(0x5C));

    hasher.update(m0.slice(0, 32));
    hasher.update(salt);
    hasher.update(m1.slice(0, 32));
    if(passphrase.length != 0) hasher.update(pin);
    c = pad1(hasher.digest(), bs);
    
    // Шаг 4. Хэшируем результат
    hasher = Streebog256.create();
    hasher.update(c.slice(0, 32))

    return hasher.digest()
}