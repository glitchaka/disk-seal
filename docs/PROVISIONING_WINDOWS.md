# Cómo autorizar una copia nueva en un pendrive

Este es el procedimiento real de emisión de licencias de disk-seal.
El pendrive autorizado **no se elige mediante un número de serie escrito a mano**.
Se determina leyendo los metadatos físicos de Windows desde el archivo
ejecutable de la unidad de destino en el momento de preparar cada copia.

## Paso 1: crear una autoridad de licencias (una sola vez)

Ejecutar en el Windows de administración, no en el pendrive del destinatario:

```powershell
New-Item -ItemType Directory -Force C:\SST-Admin | Out-Null
disk-seal.exe keygen C:\SST-Admin\authority.dskey C:\SST-Admin\authority.pub
```

`authority.dskey` contiene una clave Ed25519 cifrada con DPAPI para la
cuenta de Windows que la creó. Nunca debe añadirse a Git, copiarse al USB
del destinatario ni incluirse en una aplicación distribuida.
Conservar una copia de seguridad mediante procedimientos corporativos de
recuperación de claves: una pérdida del perfil Windows puede inutilizarla.

`authority.pub` contiene la clave pública (64 caracteres hexadecimales),
que se incorpora en el ejecutable protegido al compilarlo.
Si se genera otra autoridad y se recompila con otra clave pública, las
licencias anteriores dejarán de validarse con esa compilación.

## Paso 2: construir la plantilla protegida de HorrorMe

En la rama de prueba `test/disk-seal-integration` de `horror-me`:

```powershell
$public = (Get-Content C:\SST-Admin\authority.pub -Raw).Trim()
cmake -S . -B build-protected -A x64 -DBUILD_TESTING=OFF -DHORROR_ENABLE_DISK_SEAL=ON "-DHORROR_SEAL_PUBLIC_KEY_HEX=$public"
cmake --build build-protected --config Release
```

Esta plantilla aún **no está activada**. El modo de compilación normal no se
modifica. No distribuir el EXE maestro como una instalación autorizada.

## Paso 3: preparar y autorizar el USB de Juan

Conectar su USB, crear la carpeta de destino y usar el comando `provision`:

```powershell
New-Item -ItemType Directory -Force E:\HorrorMe | Out-Null
disk-seal.exe provision horror-me 0.4.1 C:\horror-me\build-protected\Release\HorrorMe.exe E:\HorrorMe\HorrorMe.exe Juan C:\SST-Admin\authority.dskey
```

Una ejecución correcta hace lo siguiente:

1. Genera un Installation ID único.
2. Personaliza **una copia** de la plantilla: escribe el ID dentro del nuevo `HorrorMe.exe`.
3. Inspecciona automáticamente el disco desde el que se ejecutará el archivo `E:\HorrorMe\HorrorMe.exe`.
4. Crea `E:\HorrorMe\data\installation.seal` con la huella física del USB.
5. Firma una licencia `E:\HorrorMe\data\installation.license` utilizando la clave privada del administrador.
6. Ejecuta la verificación completa de ID, firma, sello y pendrive actual.

Si la unidad no puede identificarse como USB de forma suficientemente fiable
o no devuelve serial de dispositivo físico, **la preparación falla**.
No se vuelve a emitir automáticamente otra identidad sobre el mismo destino;
se exige una copia nueva sin archivos previos.

## Paso 4: comprobar el ejecutable preparado

```powershell
& E:\HorrorMe\HorrorMe.exe --disk-seal-check
$LASTEXITCODE
```

El resultado esperado es 0. Si retorna 21, el EXE no contiene ID.
Si retorna 22, la firma, el sello o el pendrive actual no coinciden.
El código debe obtenerse a través de un proceso Windows esperado si
PowerShell no entrega el valor directamente para una aplicación gráfica.

## Paso 5: intentar copiar al pendrive de otra persona

Copiar toda la carpeta `E:\HorrorMe` al otro USB. Aunque el ejecutable
y los dos archivos de autorización sean idénticos, la biblioteca consultará
los atributos del soporte nuevo y el valor recalculado será distinto.
El juego protegido deberá rechazar el inicio con código 22.

## Repartir varias copias legítimas

Repetir el paso 3 sobre cada USB nuevo (otro Installation ID y otra licencia).
Todas las copias conservan el mismo código de juego y autoridad pública
y pueden usarse simultáneamente. **No copiar un ejecutable ya personalizado
para emitir otra instalación**: partir siempre de la plantilla maestra.

## Limitaciones y firma de código

El vínculo del soporte no proporciona resistencia absoluta a dispositivos
que imitan seriales físicos; es una barrera frente a copias ordinarias.
DPAPI protege la clave para el usuario y PC administrador, pero no sustituye
los permisos, recuperación segura y custodia de la clave.
Si se exige Authenticode, firmar el EXE ya personalizado tras el paso 3
y repetir la comprobación. La licencia USB no depende del hash del ejecutable,
para que futuras actualizaciones no invaliden la instalación.
El almacenamiento de la licencia y la integración de un autoactualizador
quedan fuera del alcance de esta prueba de HorrorMe.

Las pruebas automatizadas sin hardware real comprueban emisión y verificación
criptográfica, y rechazo con soporte simulado diferente. Para aceptación
de campo hay que conectar dos pendrives Windows de verdad.