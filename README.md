# disk-seal

`disk-seal` será una biblioteca Rust reutilizable para **ligar una instalación portable a su soporte de almacenamiento**.

Su primer consumidor previsto es Shell Shock Tool (SST), pero el diseño debe permanecer independiente de SST para poder integrarse en cualquier ejecutable o autoextraíble.

## Objetivo

Evitar que copiar un ejecutable o una instalación portable a otro disco, volumen o pendrive produzca automáticamente otra copia utilizable.

`disk-seal` **no es un sistema de licencias** y no decide quién está autorizado a usar una aplicación. Su responsabilidad es responder a otra pregunta:

> ¿Esta instalación sigue ejecutándose desde el soporte para el que fue creada?

## Caso SST

El distribuible de SST será un autoextraíble que se transporta en un pendrive y se ejecuta desde ese mismo pendrive.

Flujo previsto:

```text
SST-Setup.exe
    ↓
se copia a un pendrive
    ↓
se ejecuta desde ese pendrive
    ↓
se autoextrae en ese mismo soporte
    ↓
disk-seal identifica el soporte
    ↓
genera Installation ID + sello
    ↓
SST queda ligado a ese pendrive
```

El mismo pendrive debe poder usarse en distintos computadores. SST no debe quedar ligado al PC anfitrión.

Comportamiento esperado:

| Acción | Resultado |
| --- | --- |
| Ejecutar SST desde el pendrive original | funciona |
| Usar el mismo pendrive en otro PC | funciona |
| Copiar solo `sst.exe` al disco local | no funciona |
| Copiar `sst.exe` y el sello a otro disco | no funciona |
| Copiar toda la carpeta a otro pendrive | no funciona |
| Ejecutar desde el soporte original | funciona |

## Principios

- El soporte físico/volumen es la identidad primaria de la instalación portable.
- Para SST, **no** debe usarse el PC anfitrión como ancla obligatoria.
- No confiar en un único identificador cuando Windows permita obtener varios.
- No almacenar identificadores físicos en claro cuando puedan representarse mediante una huella.
- La fecha y hora de creación forman parte de la identidad y trazabilidad, no son el mecanismo principal de seguridad.
- La ausencia de sello, un sello inválido o un soporte distinto deben impedir el arranque de la aplicación consumidora.
- El mecanismo de licencia/autorización de usuario debe permanecer separado de `disk-seal`.

## Identidad de instalación

Cada instalación debe recibir un identificador estable, generado una sola vez, por ejemplo:

```text
SST-7A3F-91C2-6D44-8E10
```

La representación final será configurable por el consumidor. Internamente debe existir suficiente entropía aleatoria para evitar colisiones previsibles.

## Datos del sello

El modelo inicial debe contemplar al menos:

```text
installation_id
created_at
storage_fingerprint
nonce
application_id
application_version
executable_hash      # opcional según política
seal_format_version
```

Para SST, `created_at` debe conservar fecha, hora y zona/offset cuando sea posible.

## Huella del soporte

En Windows se debe intentar construir la huella usando varias señales disponibles del soporte desde el que se ejecuta la aplicación, por ejemplo:

- identificador/serial físico expuesto por el dispositivo USB o de almacenamiento;
- identificador del volumen;
- serial de volumen;
- GUID/ruta persistente del volumen cuando sea aplicable;
- un `nonce` generado durante la creación del sello.

Los identificadores brutos no deben ser la identidad pública de la instalación. Deben normalizarse y combinarse mediante una función hash criptográfica, inicialmente SHA-256.

Conceptualmente:

```text
storage_fingerprint = SHA-256(
    normalized_physical_storage_id
    || normalized_volume_id
    || installation_nonce
)
```

La implementación real debe tolerar que ciertos dispositivos no expongan todas las señales y debe registrar qué fuentes fueron utilizadas.

## Verificación en el arranque

Una aplicación consumidora podrá imponer un flujo equivalente a:

```text
¿existe el sello?
    ↓ sí
¿puede decodificarse y su formato es válido?
    ↓ sí
¿el soporte actual coincide con el soporte sellado?
    ↓ sí
¿las comprobaciones adicionales de la política pasan?
    ↓ sí
continuar ejecución
```

En cualquier fallo, la biblioteca devuelve un error estructurado y el programa consumidor decide la UX. SST deberá abortar antes de habilitar la shell.

## Política configurable

La biblioteca no debe codificar la política específica de SST. La API debe permitir combinar controles como:

```text
bind_to_volume          true/false
bind_to_physical_device true/false
require_removable_media true/false
bind_to_executable      true/false
bind_to_machine         true/false
```

Política inicial de SST:

```text
bind_to_volume          = true
bind_to_physical_device = true
require_removable_media = true
bind_to_executable      = configurable
bind_to_machine         = false
```

Ejemplos de otros consumidores:

- aplicación instalada: máquina + disco;
- herramienta portable simple: volumen solamente;
- herramienta USB estricta: dispositivo físico + volumen.

## API objetivo

La API Rust definitiva se fijará durante la implementación, pero el modelo deseado es cercano a:

```rust
use disk_seal::{SealPolicy, InstallationSeal};

let policy = SealPolicy::builder()
    .require_removable_media(true)
    .bind_to_physical_device(true)
    .bind_to_volume(true)
    .bind_to_machine(false)
    .build();

let seal = InstallationSeal::create(policy)?;
seal.save("data/installation.seal")?;
```

Y para verificar:

```rust
InstallationSeal::load("data/installation.seal")?
    .verify_current_environment()?;
```

También deberá existir una API que permita consultar, sin exponer identificadores físicos innecesarios:

- Installation ID;
- fecha/hora de creación;
- tipo de soporte detectado;
- estado de verificación;
- fuentes de identidad utilizadas.

## Separación respecto de licencias

`disk-seal` no sustituye una licencia.

```text
disk-seal
    → "esta copia pertenece a este soporte"

sistema de licencia
    → "esta persona/entidad está autorizada a usar la aplicación"
```

SST podrá combinar ambos mecanismos, pero deben permanecer desacoplados.

## Alcance de seguridad

El objetivo es impedir la copia trivial de una instalación portable a otro soporte y proporcionar una identidad estable del soporte original.

No se pretende afirmar que un identificador de hardware sea imposible de falsificar ni convertir `disk-seal` en DRM invulnerable. La resistencia debe venir de combinar señales, validar coherencia y evitar depender de un único serial fácilmente reproducible.

## Distribución autoextraíble

`disk-seal` debe ser usable por un autoextraíble/instalador que:

1. determine el volumen desde el que se está ejecutando;
2. extraiga la aplicación en ese soporte;
3. genere el sello una única vez;
4. deje el sello junto a los datos de la instalación;
5. lance la aplicación ya sellada.

La construcción concreta del autoextraíble puede vivir en el proyecto consumidor; `disk-seal` debe proporcionar las primitivas de identidad, creación y verificación.

## Uso actual como biblioteca y CLI

La biblioteca puede consumirse desde un instalador Rust o desde SST mediante
una dependencia Git del repositorio. Las funciones disponibles son:

- `inspect_storage(exe)`: informa sin exponer seriales si el soporte parece
  apto para un sello portátil.
- `InstallationSeal::create("sst", version, exe, policy)`: calcula el sello.
- `save_new(path)`: escribe un archivo nuevo, negándose a sobrescribirlo.
- `load(path)` + `verify_for_application("sst", exe)`: valida el soporte
  original y la identidad de la aplicación.

La CLI `disk-seal` dispone de tres operaciones:

```powershell
cargo run -- inspect E:\SST\sst.exe
cargo run -- create sst 0.1.9-blue.27 E:\SST\sst.exe E:\SST\data\installation.seal
cargo run -- verify sst E:\SST\sst.exe E:\SST\data\installation.seal
```

En condiciones normales, `create` debe ejecutarse **una sola vez**, durante
la entrega, sobre el soporte original. Si falta el serial físico o Windows no
reconoce el dispositivo como extraíble/USB, la política estricta rechaza el
sellado; no se genera un sello débil automáticamente.

### Limitación de la prueba automática

GitHub Actions ejecuta pruebas de lógica, compilación y la CLI en Windows y
Linux. Los agentes virtuales no disponen de un pendrive USB físico asignado;
la aceptación en hardware real (variantes NTFS, exFAT, FAT32 y dispositivos
cuya ruta cambia entre equipos) exige una prueba de campo en Windows. Este
módulo no debe considerarse una solución anti-clonación invulnerable.

**Importante:** un sello JSON aislado no proporciona autenticidad criptográfica.
SST debe vincular el `installation_id` y la `storage_fingerprint` a una
licencia **firmada por la autoridad de activación**, y comprobar esa firma
antes de habilitar funciones privilegiadas. No incluir claves privadas de
firma en el pendrive ni el ejecutable.

## Implementación inicial

La biblioteca `disk-seal` ya contiene una primera implementación Windows: crea un
Installation ID aleatorio, un nonce de 256 bits y una huella SHA-256 de serial
del soporte + serial del volumen + sistema de archivos. Los seriales en bruto
nunca se guardan en el sello. El sello se verifica contra el dispositivo desde
el que se ejecuta el binario, y se rechaza un dispositivo o volumen diferente.

La API disponible es `SealPolicy::portable_usb()`,
`InstallationSeal::create(app_id, version, exe_path, policy)`,
`InstallationSeal::save_new(path)`,
`InstallationSeal::load(path)` y
`InstallationSeal::verify_current_environment(exe_path)`.

El modo estricto **rechaza dispositivos que Windows clasifica DRIVE_FIXED**
y cualquier soporte que no permita obtener un serial físico. Esto debe
resolverse mediante políticas aprobadas antes de entregar a terceros.

### Seguridad y límites

- Esta biblioteca **no crea ni valida licencias firmadas**; SST necesita un
  módulo de activación separado y una clave pública embebida.
- La huella física no es una identidad criptográfica: un atacante capaz de
  falsificar las propiedades del dispositivo o modificar el programa puede
  eludir un sello. La licencia firmada complementa la comprobación.
- No se ha conectado todavía con la secuencia de arranque ni el autoextraíble
  de SST. No se debe afirmar que las instalaciones entregadas están protegidas.
- La API todavía está en desarrollo; no se declara probada en hardware Windows.

## Estado

Primera implementación de biblioteca incorporada; pendiente de integración
y comprobación sobre dispositivos USB reales.
