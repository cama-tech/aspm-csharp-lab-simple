# Laboratorio ASPM en C#

Solución .NET 8 deliberadamente vulnerable para pruebas controladas. Contiene una aplicación web y un proyecto xUnit.

> Ejecutar únicamente en `127.0.0.1` o en un entorno aislado. No publicar en Internet ni usar datos reales.

## Estructura

```text
AspmLab.sln
├── src/AspmLab                 Aplicación web vulnerable
├── tests/AspmLab.Tests         Pruebas xUnit
├── fixtures/sca                Dependencias antiguas para SCA y SBOM
├── fixtures/secrets            Secretos sintéticos y falsos positivos
├── infra                       Terraform vulnerable para IaC
├── Dockerfile                  Caso vulnerable de contenedor
└── evidence/expected-findings.json
```

## Ejecutar las pruebas

```bash
dotnet restore AspmLab.sln
dotnet test AspmLab.sln
```

Las pruebas comprueban que existen y funcionan los casos de:

- SAST;
- SCA;
- secretos;
- SBOM;
- infraestructura como código;
- contenedores;
- DAST;
- falsos positivos;
- severidades crítica, alta, media y baja;
- vulnerabilidades de lógica de negocio.

Algunas pruebas pasan cuando encuentran una conducta vulnerable. Eso es intencional y no significa que la vulnerabilidad esté corregida.

## Ejecutar la aplicación

```bash
dotnet run --project src/AspmLab/AspmLab.csproj
```

La aplicación quedará disponible en la dirección que muestre .NET. Para fijar el puerto:

```bash
dotnet run --project src/AspmLab/AspmLab.csproj --urls http://127.0.0.1:8080
```

Comprobación:

```bash
curl http://127.0.0.1:8080/health
```

Resultado esperado:

```json
{"status":"ok"}
```

## Probar con Swagger

Con la aplicación ejecutándose, abre:

```text
http://127.0.0.1:8080/swagger
```

Swagger permite consultar los endpoints y enviar datos de prueba desde el navegador. Usa solamente datos ficticios. El documento OpenAPI se encuentra en:

```text
http://127.0.0.1:8080/swagger/v1/swagger.json
```

## Ejecutar con Docker

```bash
docker compose up --build
```

Detener:

```bash
docker compose down --volumes
```

## Casos de negocio incluidos

| Caso | Conducta vulnerable validada |
|---|---|
| `BUSINESS-CRITICAL-001` | Un usuario sin rol autorizado puede aprobar una orden. |
| `BUSINESS-HIGH-001` | Un usuario consulta la orden de otro usuario. |
| `BUSINESS-HIGH-002` | La aplicación acepta un importe alterado por el cliente. |
| `BUSINESS-MEDIUM-001` | Una transferencia duplicada se procesa dos veces. |
| `BUSINESS-MEDIUM-002` | El límite se evita dividiendo el monto. |

El catálogo completo está en `evidence/expected-findings.json`.

## Ejecución controlada de comandos

Desde Swagger puede probarse `GET /api/diagnostic` con uno de estos valores:

```text
whoami
pwd
date -u
```

Ejemplo:

```bash
curl "http://127.0.0.1:8080/api/diagnostic?command=whoami"
```

La respuesta indica el comando, la salida y el código de finalización. Cualquier valor diferente se rechaza con HTTP `400`; no agregue nuevos comandos a la lista permitida.

## Descargar el registro de resultados

La aplicación registra automáticamente cada endpoint vulnerable ejecutado. En Swagger:

1. Use `DELETE /api/lab-results` para limpiar resultados anteriores.
2. Ejecute las pruebas que desea validar.
3. Use `GET /api/lab-results` para revisar el registro.
4. Use `GET /api/lab-results/export` y descargue `aspm-lab-results.json`.

También puede registrar manualmente un resultado mediante `POST /api/lab-results`, indicando el caso, resultado esperado, resultado observado y si la prueba pasó.

Adjunte el archivo `aspm-lab-results.json` para comparar los resultados obtenidos con los casos esperados.

Cada registro funcional incluye automáticamente:

- `TestRunId`, versión de la aplicación y ambiente;
- hora de inicio, hora de finalización y duración;
- estado HTTP esperado y observado;
- aserción evaluada y resultado `Passed` (`true` o `false`);
- motivo del fallo, cuando corresponda;
- evidencia específica del caso, por ejemplo salida presente, encabezado `Location`, ruta resuelta, confirmación de escritura en log o configuración de deserialización.

Para `NEW-SAST-001` ejecute dos solicitudes: una permitida (`whoami`) y otra rechazada (`whoami; id`). Ambas deben registrar `Passed: true`, porque la primera demuestra la ejecución controlada y la segunda demuestra que la protección del laboratorio impide comandos no autorizados.

El caso `SAST-FP-001` confirma automáticamente que el identificador público ficticio está presente. Su clasificación como falso positivo sigue requiriendo el resultado del escáner, porque la aplicación no puede decidir qué alerta generará una herramienta SAST externa.

## Importar el resultado SAST automáticamente

Si el SAST genera SARIF:

1. Abra `POST /api/lab-results/import-sarif` en Swagger.
2. Seleccione el archivo `.sarif` o `.json`.
3. Ejecute la importación.
4. Revise el resumen `imported`, `mapped` y `unmapped`.
5. Consulte `GET /api/lab-results`.
6. Descargue el resultado completo con `GET /api/lab-results/export`.

La importación obtiene automáticamente:

- herramienta y versión;
- regla;
- severidad;
- mensaje;
- archivo y línea;
- caso esperado relacionado.

Los hallazgos que no puedan relacionarse reciben el ID `SAST-UNMAPPED`. Los posibles falsos positivos quedan pendientes de clasificación manual porque esa decisión no puede obtenerse de SARIF.

## Importar y exportar resultados SCA

Genere el resultado SCA desde la raíz del repositorio:

```powershell
dotnet list .\src\AspmLab\AspmLab.csproj package `
  --vulnerable `
  --include-transitive `
  --format json |
  Out-File .\sca-results.json -Encoding utf8
```

En Swagger:

1. Use `POST /api/lab-results/import-sca` y seleccione `sca-results.json`.
2. Revise exclusivamente los resultados SCA con `GET /api/lab-results/sca`.
3. Descargue `aspm-sca-results.json` con `GET /api/lab-results/export/sca`.

El importador registra paquete, versión solicitada y resuelta, tipo de dependencia, framework, URL del aviso, severidad y proyecto afectado. Los paquetes que no correspondan al catálogo conocido se guardan como `SCA-UNMAPPED` para revisión manual. El export general continúa disponible y no cambia su comportamiento.

El export SCA incluye `GeneratedAtUtc`, `TestRunId`, un resumen y el detalle de resultados. El resumen indica casos esperados aprobados, fallidos y pendientes, hallazgos importados y hallazgos no mapeados. El log compara automáticamente las versiones esperadas y registra como fallido cualquier paquete esperado que no aparezca. Incluye casos críticos, altos, múltiples y bajos, además de `SCA-FP-001`, un control negativo que solo existe como texto y no debe aparecer como dependencia instalada. Para `SCA-MULTI-001` exige al menos dos avisos asociados con ImageSharp. Una diferencia de severidad se conserva en la evidencia como `severityMatches=false`, pero no convierte por sí sola una detección correcta en fallo.

### Secretos con Gitleaks

```powershell
gitleaks detect --no-git --source . --config .gitleaks.toml --report-format json --report-path gitleaks-results.json --no-banner
```

Importe `gitleaks-results.json` mediante `POST /api/lab-results/import-secrets` y descargue el resultado con `GET /api/lab-results/export/secrets`. El archivo `aspm-secrets-results.json` contiene los casos crítico, alto, medio y bajo, además del control `SECRET-FP-001`. Los valores encontrados nunca se copian al export: el campo `Input` queda como `[REDACTED]`.

### Export exclusivo de SAST

Importe el SARIF mediante `POST /api/lab-results/import-sarif`. Consulte solamente los resultados SAST con `GET /api/lab-results/sast` y descargue `aspm-sast-results.json` mediante `GET /api/lab-results/export/sast`. Antes de importar SARIF, el export presenta los siete casos como pendientes; `Passed=null` significa no probado y no un error.

Los registros funcionales generados al ejecutar los endpoints vulnerables no se cuentan como detecciones SAST. Solamente los resultados importados desde SARIF pueden aprobar los casos del export SAST.

### Inventario de componentes SBOM

Instale CycloneDX para .NET y genere el inventario desde la raíz del repositorio:

```powershell
dotnet tool install --global CycloneDX
dotnet CycloneDX .\src\AspmLab\AspmLab.csproj -o .\artifacts\sbom -j
```

Luego, en Swagger:

1. Use `POST /api/lab-results/import-sbom` y seleccione `artifacts/sbom/bom.json`.
2. Consulte los registros SBOM con `GET /api/lab-results/sbom`.
3. Descargue `aspm-sbom-results.json` con `GET /api/lab-results/export/sbom`.

El export valida nueve casos: aplicación principal, cinco dependencias directas, al menos una dependencia transitiva, información de licencia y el control negativo `Fake.Vulnerable.Package`. Este último solo está mencionado como texto y no debe aparecer como componente real. Antes de importar `bom.json`, los nueve casos aparecen con `Passed=null` y estado pendiente.

### Infraestructura como código con Checkov

Genere el reporte desde la raíz del repositorio sin aplicar los recursos Terraform:

```powershell
checkov -d .\infra --output json | Out-File .\checkov-results.json -Encoding utf8
```

Luego, en Swagger:

1. Use `POST /api/lab-results/import-iac` y adjunte `checkov-results.json`.
2. Consulte exclusivamente IaC con `GET /api/lab-results/iac`.
3. Descargue `aspm-iac-results.json` mediante `GET /api/lab-results/export/iac`.

El export controla cuatro configuraciones inseguras y `IAC-FP-001`, que valida que el CIDR local `127.0.0.1/32` no se clasifique como exposición pública. Las alertas adicionales quedan como `IAC-UNMAPPED` para revisión manual. Antes de importar el reporte, los cinco casos aparecen pendientes y no se consideran fallidos.

### Seguridad de contenedores con Trivy

Construya la imagen y genere dos reportes:

```powershell
docker build -t aspm-lab:local .

trivy image --scanners vuln --format json `
  --output trivy-image-results.json aspm-lab:local

trivy config --format json `
  --output trivy-config-results.json .
```

En Swagger, importe ambos archivos —uno después del otro— mediante `POST /api/lab-results/import-container`. No elimine los resultados entre ambas importaciones. Después:

1. Consulte solo contenedores con `GET /api/lab-results/container`.
2. Descargue `aspm-container-results.json` con `GET /api/lab-results/export/container`.

El export contiene siete casos: vulnerabilidades crítica, alta, media y baja dentro de la imagen; ejecución como root; ausencia de `HEALTHCHECK`; y el control negativo que confirma que `127.0.0.1:8080:8080` no es exposición pública. Los hallazgos adicionales se conservan como `CONTAINER-UNMAPPED`. La base de vulnerabilidades de Trivy cambia con el tiempo, por lo que el export conserva la severidad observada y deja pendiente cualquier caso esperado que no tenga evidencia importada.

### Aplicación en funcionamiento con OWASP ZAP

Levante el laboratorio y genere el reporte JSON:

```powershell
docker compose up --build -d

docker run --rm `
  -v "${PWD}:/zap/wrk/:rw" `
  ghcr.io/zaproxy/zaproxy:stable `
  zap-full-scan.py `
  -t http://host.docker.internal:8080 `
  -J zap-results.json `
  -r zap-report.html
```

En Swagger:

1. Importe `zap-results.json` mediante `POST /api/lab-results/import-dast`.
2. Consulte solamente las alertas DAST con `GET /api/lab-results/dast`.
3. Descargue `aspm-dast-results.json` mediante `GET /api/lab-results/export/dast`.

El export controla seis casos: ejecución controlada de comandos, XSS reflejado, path traversal, redirección abierta, cabeceras ausentes y el control negativo `/health`. Los registros funcionales creados desde Swagger no cuentan como detecciones de ZAP. Cada alerta importada conserva plugin, URL, método, parámetro, ataque, evidencia, riesgo y confianza. Las alertas adicionales quedan como `DAST-UNMAPPED`.
