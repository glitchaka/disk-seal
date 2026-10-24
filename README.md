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

## Estado

Diseño inicial reservado. Aún no se ha fijado una API estable ni se ha realizado implementación.
