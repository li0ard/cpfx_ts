<p align="center">
    <b>@li0ard/cpfx</b><br>
    <b>Декодер PFX и ключевого контейнера КриптоПро</b>
    <br>
    <a href="https://li0ard.is-cool.dev/cpfx_ts">docs</a>
    <br><br>
    <a href="https://github.com/li0ard/cpfx_ts/actions/workflows/test.yml"><img src="https://github.com/li0ard/cpfx_ts/actions/workflows/test.yml/badge.svg" /></a>
    <a href="https://github.com/li0ard/cpfx_ts/blob/main/LICENSE"><img src="https://img.shields.io/github/license/li0ard/cpfx_ts" /></a>
    <br>
    <a href="https://npmjs.com/package/@li0ard/cpfx"><img src="https://img.shields.io/npm/v/@li0ard/cpfx" /></a>
    <br>
    <hr>
</p>

## Установка

```bash
npm i @li0ard/cpfx
```

## Использование
### Декодирование PFX (cpfx)
```ts
import { proceed_pfx, encodePrivateKeyToPem } from "@li0ard/cpfx";

const file = await Bun.file("/path/to.pfx").bytes();
const exported = await proceedPFX(file, "password");

console.log(encodePrivateKeyToPem(exported));
```

### Декодирование ключевого контейнера (ckey)
```ts
import { proceed_cryptopro, encodePrivateKeyToPem } from "@li0ard/cpfx";

const headerKey = await Bun.file("/path/to/header.key").bytes();
const masksKey = await Bun.file("/path/to/masks.key").bytes();
const primaryKey = await Bun.file("/path/to/primary.key").bytes();
const exported = await proceed_cryptopro(
    headerKey,
    masksKey,
    primaryKey,
    "password"
);

console.log(encodePrivateKeyToPem(exported));
```

### Изменение флага экспортируемости
```ts
import { changeContainerExportable } from "@li0ard/cpfx";

const headerKey = Bun.file("/path/to/header.key");
const newHeaderKey = changeContainerExportable(await file.bytes(), true); // Разрешить экспорт

await headerKey.write(newHeaderKey);
```

## Ссылки
- [Статья про cpfx на Хабре](https://habr.com/ru/articles/693600/)
- [Статья про ckey на Хабре](https://habr.com/ru/articles/823772/)
- [Цикл статей в блоге](https://blog.li0ard.rest/+anticryptopro)