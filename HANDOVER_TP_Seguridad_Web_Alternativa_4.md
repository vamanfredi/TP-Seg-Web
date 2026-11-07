# Handover para desarrollar el TP de Seguridad en Aplicaciones Web

## 1. Objetivo y estado del trabajo

Desarrollar un laboratorio web local para el trabajo práctico tradicional de la cátedra **Seguridad en Aplicaciones Web de UTN FRBA**. La propuesta elegida es la alternativa 4: **Acceso no autorizado a exportaciones confidenciales**.

Ya se redactó la entrega preliminar. En esta conversación no se implementó la aplicación ni se ejecutaron los ataques. El siguiente paso es comenzar el desarrollo en la carpeta de proyecto abierta en Codex Desktop. Si allí existe código, inspeccionarlo antes de crear o reemplazar archivos.

La entrega preliminar establece el escenario, Flask, SQLite, el contenedor local y la cadena de cuatro fallas. Los contratos HTTP, el esquema de datos, los nombres de archivos y la configuración que se detallan aquí son decisiones para concretar la implementación. Pueden ajustarse si el repositorio lo requiere, conservando las cuatro causas y sus dependencias.

Este archivo contiene el contexto necesario para comenzar sin acceder a la conversación anterior.

## 2. Instrucción para iniciar en Codex Desktop

Copiar este Markdown a la carpeta del proyecto y utilizar este mensaje:

```text
Leé completo HANDOVER_TP_Seguridad_Web_Alternativa_4.md y revisá las instrucciones
AGENTS.md que correspondan a esta carpeta. Inspeccioná el repositorio y comenzá
a implementar el laboratorio descrito.

Conservá la cadena A01 → A07 → A05 → A10 y el escenario de exportaciones
confidenciales. Implementá las fallas intencionales y sus correcciones con
configuración independiente, usando la misma aplicación y los mismos datos.

Primero construí el entorno, la semilla y las operaciones legítimas. Después
incorporá las cuatro fallas y verificá la cadena completa por HTTP. Continuá
con pruebas de aceptación, una interfaz sencilla y documentación de ejecución.

Resolvé las decisiones menores con este handover y el código existente.
Preservá los archivos ajenos al proyecto. Informá qué implementaste, qué
pruebas ejecutaste y qué quedó pendiente, sin presentar resultados esperados
como pruebas realizadas.
```

## 3. Escenario y resultado que debe demostrarse

La aplicación será un portal empresarial con tres funciones: consulta de tickets de soporte, búsqueda de exportaciones y descarga de archivos CSV.

| Cuenta | Acceso legítimo |
| --- | --- |
| Cliente de empresa A | Consultar sus propios tickets y acceder a su propio buzón de recuperación del laboratorio. |
| Operador de empresa B | Buscar exportaciones generales de B y descargarlas. No puede descargar exportaciones confidenciales. |
| Supervisor de empresa B | Buscar y descargar exportaciones generales y confidenciales de B. |

El atacante comienza únicamente con las credenciales del cliente de A. No conoce el UUID ni el usuario de inicio de sesión del operador objetivo, su contraseña ni el UUID del CSV confidencial. Tiene acceso al correo de su propia cuenta mediante un buzón local simulado.

**Resultado final:** descargar un CSV confidencial de B utilizando una sesión de operador que no tiene ese permiso. Para el mismo operador y archivo, una solicitud normal deberá devolver **403**, mientras que la solicitud que provoca la excepción deberá devolver **200 con el CSV**, cuando A10 esté habilitada.

## 4. Cadena que debe conservarse

Se utiliza **OWASP Top 10 Web 2025**, correspondiente a las categorías desarrolladas en el PDF 2026 de la cátedra. No mezclar su numeración con OWASP Web 2021 o API Security 2023.

| Etapa | Categoría OWASP | Causa concreta | Resultado utilizado en la etapa siguiente |
| --- | --- | --- | --- |
| T1 | A01 Broken Access Control | La lectura de un ticket por ID omite verificar su pertenencia. | UUID y nombre de usuario del operador asignado a un ticket privado de B. |
| T2 | A07 Authentication Failures | El restablecimiento valida un token, pero no su vinculación con la cuenta cuya contraseña modifica. | Contraseña del operador modificada y posterior sesión de operador. |
| T3 | A05 Injection | El buscador concatena una entrada dentro de una consulta SQL. | UUID de una exportación confidencial que no aparece en la búsqueda legítima. |
| T4 | A10 Mishandling of Exceptional Conditions | Una excepción del adaptador de permisos se interpreta como autorización para continuar. | Descarga del contenido del CSV confidencial. |

T2 debe demostrar una falla en la recuperación de identidad. Iniciar sesión con la contraseña obtenida es una transición normal. T4 debe demostrar una decisión permisiva causada por una excepción real; devolver un error 500 o escribir una respuesta 200 ficticia no alcanza.

A01 y A10 afectan controles diferentes: pertenencia del ticket y evaluación del permiso de descarga, respectivamente. La inyección SQL debe revelar metadatos; el contenido del CSV solo se obtiene en T4.

## 5. Arquitectura y decisiones de implementación

### Aplicación

- Python y Flask, con `create_app(config)` y módulos pequeños para autenticación, tickets, exportaciones, permisos y utilidades del laboratorio.
- HTML con Jinja y JavaScript mínimo. La interfaz y las API compartirán la lógica de negocio.
- Un servicio `web` en Docker Compose. El adaptador de autorización será un módulo local que simule una integración; no hace falta otro servicio HTTP.
- `pytest` con el cliente de pruebas de Flask para integración, y un guion HTTP independiente para demostrar la cadena contra el contenedor.
- Elegir versiones compatibles y fijarlas en el proyecto al instalar. Registrar las versiones realmente utilizadas en el README.

La fábrica de aplicaciones permite aislar configuraciones y datos por prueba. El cliente de Flask permite ejecutar solicitudes de integración sin iniciar un servidor real. Referencias: [Application Factories](https://flask.palletsprojects.com/en/stable/patterns/appfactories/) y [Testing Flask Applications](https://flask.palletsprojects.com/en/stable/testing/).

### Persistencia

| Recurso | Contenido | Acceso previsto |
| --- | --- | --- |
| `core.sqlite` | Empresas, usuarios, sesiones, tokens de recuperación, tickets y mensajes del buzón local. | Consultas parametrizadas. Escrituras controladas por los flujos de la aplicación. |
| `catalog.sqlite` | UUID, empresa, título y clasificación de las exportaciones. | El buscador abre una conexión de solo lectura. La semilla se escribe desde el inicializador del laboratorio. |
| Directorio privado `exports/` | Archivos CSV con contenido ficticio. | Solo se sirven después del control de descarga. No pertenece a `static/`. |

El catálogo no almacenará el contenido de los CSV, contraseñas, tokens ni sesiones. La conexión del buscador no adjuntará `core.sqlite`, no habilitará extensiones ni funciones para leer archivos y no utilizará `executescript`. Usar una consulta por `execute` y restringir operaciones como `ATTACH` con el autorizador de SQLite. En el modo corregido, parametrizar también el texto de búsqueda. Estas restricciones conservan el papel específico de T3 en la cadena. Referencia técnica: [sqlite3](https://docs.python.org/3/library/sqlite3.html).

### Ejecución local

Publicar el puerto como `127.0.0.1:8000:8000`. Dentro del contenedor, el proceso puede escuchar en `0.0.0.0:8000`. La publicación explícita en loopback está contemplada en la [referencia de puertos de Compose](https://docs.docker.com/reference/compose-file/services/#ports).

Usar datos ficticios y un volumen del proyecto para las bases y los CSV. El laboratorio no requiere correo externo, infraestructura empresarial ni servicios de terceros. Ejecutar el contenedor sin privilegios, sin socket de Docker y con el depurador interactivo de Flask deshabilitado.

## 6. Modelo mínimo de datos y semilla

Los nombres siguientes son una base para implementar; no es necesario introducir un ORM.

| Entidad | Campos principales |
| --- | --- |
| `organizations` | `id`, `name` |
| `users` | `id` UUID, `organization_id`, `username`, `email`, `password_hash`, `role` |
| `sessions` | Identificador opaco, `user_id`, vencimiento y estado de revocación; soporte para el mecanismo CSRF elegido. |
| `password_reset_tokens` | Hash del token, `user_id` de emisión, `expires_at`, `consumed_at`. |
| `tickets` | `id` entero, `organization_id`, `owner_user_id`, `assigned_operator_id`, asunto y descripción. |
| `lab_messages` | `id`, `recipient_user_id`, cuerpo del mensaje y fecha. |
| `exports` en el catálogo | `id` UUID, `organization_id`, `title`, `is_confidential`. |

La semilla deberá generar:

1. Empresa A y empresa B.
2. Cliente atacante de A, operador objetivo de B y supervisor de B.
3. Ticket `1001` del cliente de A, sin operador asignado. Su consulta legítima no revela la identidad objetivo.
4. Ticket `1002` privado de B, con el operador objetivo asignado. La respuesta incluirá su UUID y nombre de usuario, sin contraseñas ni tokens.
5. Una exportación general de B y una confidencial de B; puede agregarse una general de A para comprobar separación entre empresas.
6. CSV confidencial con un marcador verificable, por ejemplo `DEMO_EXPORT_B_CONFIDENTIAL`, presente en el archivo y ausente del catálogo.

Generar UUID impredecibles al reiniciar la semilla. La estructura y los casos serán reproducibles aunque cambien sus valores. El guion de ataque debe descubrir los identificadores desde las respuestas, sin leer archivos internos ni insertar los UUID conocidos por la preparación de la prueba.

Entregar al atacante solo sus credenciales. Las credenciales de operador y supervisor servirán para las pruebas legítimas del desarrollador, mediante una salida local de inicialización separada; no deben estar en las páginas, el JavaScript ni las respuestas visibles para el atacante. La contraseña inicial del operador debe ser aleatoria y no deducible de la del cliente.

El comando de reinicio restaurará contraseñas, tickets, exportaciones, sesiones, tokens y mensajes. Solo afectará los datos generados dentro del directorio del laboratorio.

## 7. Contratos HTTP

Las rutas siguientes son el contrato propuesto para el desarrollo. Aún deben implementarse. Las respuestas de API serán JSON, excepto la descarga del CSV.

| Método y ruta | Entrada principal | Comportamiento |
| --- | --- | --- |
| `GET /health` | Ninguna. | Estado básico sin secretos. |
| `GET /api/session` | Cookie si existe. | Estado de sesión, identidad propia cuando corresponda y token CSRF. Puede inicializar una sesión anónima para los formularios. |
| `POST /api/auth/login` | `username`, `password` | Autenticar y renovar la sesión. |
| `POST /api/auth/logout` | Sesión y CSRF. | Revocar la sesión en el servidor. |
| `GET /api/tickets` | Sesión cliente. | Listar únicamente los tickets propios en ambos modos. |
| `GET /api/tickets/{id}` | Sesión cliente. | Punto de T1. Control de pertenencia según A01. |
| `POST /api/auth/recovery` | `username` | Emitir un token y enviar el mensaje al buzón local del destinatario. Respuesta genérica 202, sin token. |
| `GET /lab/inbox` | Sesión cliente. | Mostrar solo los mensajes cuyo destinatario es el usuario de esa sesión. |
| `POST /api/auth/reset-password` | `token`, `user_id`, `new_password` | Punto de T2. Validar token y, según A07, vinculación con la cuenta objetivo. |
| `GET /api/exports/search?q=...` | Sesión de operador o supervisor. | Punto de T3. Devolver metadatos de exportaciones. |
| `POST /api/exports/{uuid}/download` | Sesión, CSRF y JSON con `context`. | Punto de T4. Evaluar permisos y entregar el CSV únicamente si la decisión permite continuar. |

Usar **401** sin autenticación, **403** ante permisos insuficientes, **404** para recursos inexistentes y **400** para entradas inválidas. El rechazo de un token ajeno en el modo corregido será 400.

Proteger las operaciones que modifican estado con CSRF. El guion HTTP deberá obtener y enviar el token válido: el laboratorio no depende de una falla CSRF. La identidad y los permisos se resolverán en el servidor, sin aceptar `role`, `allowed` o `is_admin` enviados por el cliente.

Usar sesiones opacas revocables y cookies `HttpOnly` y `SameSite`. Ajustar `Secure` al uso de HTTP local o HTTPS. Mantener hash de contraseñas adecuado, escape de HTML y mensajes de error sin trazas internas. La única consulta SQL deliberadamente concatenada estará en el buscador de exportaciones.

## 8. Implementación de cada falla y su corrección

### T1 — A01 en la lectura de tickets

**Vulnerable:** exigir autenticación, buscar el ticket por ID y devolverlo sin comprobar propietario ni empresa. El cliente podrá modificar `1001` por `1002` y obtener la identidad del operador.

**Corregido:** comprobar empresa y propietario del ticket antes de devolver sus datos. Para este contrato, un ticket existente pero ajeno devolverá 403.

Conservar el listado de tickets correctamente filtrado en ambos modos. El UUID del operador objetivo no debe aparecer en el ticket propio, el listado, un directorio público de usuarios o el HTML inicial.

### T2 — A07 en la recuperación de contraseña

El atacante solicitará recuperación para su propio usuario, leerá ese token en su buzón y lo enviará junto con el UUID del operador obtenido en T1.

**Vulnerable:** validar existencia, vencimiento y uso del token, pero actualizar la contraseña del `user_id` indicado en la solicitud sin compararlo con el usuario de emisión.

**Corregido:** exigir coincidencia entre ambos usuarios, o resolver el usuario únicamente desde el token. Con el contrato propuesto, rechazar la discrepancia con 400 y no modificar ninguna contraseña.

En ambos modos, un restablecimiento exitoso consumirá el token y revocará las sesiones de la cuenta modificada. Los tokens inválidos, vencidos y consumidos se rechazarán. Así la falla demostrada será la vinculación incorrecta, sin depender de tokens predecibles o reutilizables.

El restablecimiento no iniciará sesión automáticamente. El guion abrirá después una sesión de operador usando el nombre obtenido en T1 y la contraseña elegida en T2.

### T3 — A05 en el buscador de exportaciones

La búsqueda normal de un operador devolverá exportaciones generales de su empresa. Un supervisor podrá consultar también las confidenciales de su empresa. La cuenta cliente recibirá 403 en esta función.

**Vulnerable:** incorporar `q` por concatenación a una consulta SQL real sobre `catalog.sqlite`. La prueba deberá alterar la selección y revelar el UUID confidencial de B. No simular el resultado mediante una condición que reconozca un texto especial.

**Corregido:** utilizar parámetros, conservando los filtros de empresa y confidencialidad. La misma entrada se tratará como texto y no revelará el UUID protegido.

El payload concreto se definirá al implementar la consulta y se documentará después de verificarlo contra el laboratorio. La conexión de búsqueda no podrá modificar datos ni acceder a `core.sqlite` o al contenido de los CSV.

### T4 — A10 en el adaptador de autorización

Usar JSON válido para ambas solicitudes; lo que cambiará será el tipo del campo `context`.

Solicitud normal:

```json
{"context": {"purpose": "download"}}
```

Solicitud que provocará la excepción:

```json
{"context": null}
```

El flujo de descarga tendrá este orden:

1. Validar autenticación, tipo de cuenta, CSRF, UUID y existencia de la exportación.
2. Analizar el JSON y exigir un objeto externo con la clave `context`. Un JSON mal formado será 400 en ambos modos.
3. Resolver usuario, empresa y clasificación de la exportación desde el servidor.
4. Llamar al adaptador. En la implementación vulnerable, este asumirá que `context` es un objeto y accederá a uno de sus campos, provocando una excepción real cuando sea `null`.
5. Si no hay excepción, evaluar normalmente el permiso: operador sobre archivo confidencial produce 403; supervisor autorizado produce 200.
6. **Con A10 habilitada**, capturar la excepción del adaptador y continuar indebidamente con la descarga.
7. **Con A10 corregida**, validar el tipo y devolver 400 para `context: null`. Si ocurre otra excepción inesperada del adaptador, responder 503 sin entregar el archivo.

El bloque que permite continuar ante errores abarcará solamente la evaluación del adaptador. No debe convertir fallas de autenticación, UUID inexistentes o errores de lectura de archivos en permisos de descarga. `context.purpose` será un dato auxiliar: nunca otorgará permisos por su valor.

La evidencia principal comparará **la misma sesión y el mismo UUID**: contexto válido → 403; contexto inválido → 200 y bytes reales del CSV en modo vulnerable. No hace falta apagar un servicio ni manipular privilegios del host para provocar la excepción.

## 9. Configuración de los modos

Implementar cuatro opciones independientes, leídas al iniciar la aplicación. No exponer cambios de modo mediante parámetros HTTP o botones de la aplicación.

| Variable | Valor `1` | Valor `0` |
| --- | --- | --- |
| `VULN_A01` | Omite pertenencia en lectura del ticket. | Comprueba empresa y propietario. |
| `VULN_A07` | Acepta discrepancia entre token y cuenta objetivo. | Verifica la vinculación. |
| `VULN_A05` | Concatena la entrada del buscador en SQL. | Parametriza la consulta. |
| `VULN_A10` | Continúa ante una excepción del adaptador. | Valida el contexto y deniega ante errores. |

Preparar un `.env.example` para el laboratorio:

```dotenv
LAB_MODE=1
VULN_A01=1
VULN_A07=1
VULN_A05=1
VULN_A10=1
APP_DATA_DIR=/data
RESET_TOKEN_TTL_SECONDS=600
```

Parsear los valores como booleanos explícitos; la cadena `"0"` debe significar falso. Sin configuración, las cuatro fallas estarán deshabilitadas. Rechazar una configuración con fallas habilitadas y `LAB_MODE` distinto de `1`.

Permitir inyectar estos valores en `create_app` para las pruebas. Para pasar a modo corregido durante la demostración, establecer las cuatro opciones en `0` y recrear el servicio. Conservar el mismo modelo y las operaciones legítimas.

## 10. Interfaz y estructura de archivos

La interfaz tendrá inicio de sesión, listado y detalle de tickets, solicitud y confirmación de recuperación, buzón local propio, buscador de exportaciones y acción de descarga. La UI de descarga enviará el contexto válido; la alteración para T4 se realizará mediante Burp o el guion HTTP.

Las páginas deben parecer un portal sencillo y funcional. Los payloads, los modos de vulnerabilidad y las credenciales de preparación permanecerán en la documentación y las utilidades de desarrollo.

| Ruta propuesta | Responsabilidad |
| --- | --- |
| `app/__init__.py` | Fábrica de aplicación y registro de módulos. |
| `app/config.py` | Configuración y selección de modos. |
| `app/db.py` | Conexiones separadas y control del acceso al catálogo. |
| `app/auth.py` | Sesiones, recuperación y restablecimiento. |
| `app/tickets.py` | Listado y consulta del ticket. |
| `app/exports.py` | Búsqueda y descarga. |
| `app/authorization.py` | Política de permisos y adaptador. |
| `app/lab.py` | Semilla, reinicio y buzón simulado. |
| `app/templates/` y `app/static/` | Interfaz y recursos locales. |
| `tests/` | Pruebas de comportamiento y de la cadena. |
| `scripts/demo_chain.py` | Reproducción HTTP de T1 a T4. |
| `docs/demo.md` | Pasos manuales, evidencias y comparación. |
| `Dockerfile`, `compose.yaml`, `.env.example` | Ejecución reproducible. |
| `README.md` | Arranque, cuentas de laboratorio, modos y pruebas. |

Esta es una estructura inicial, no un listado de archivos ya existentes. Mantener una organización equivalente si el repositorio ya tiene convenciones.

## 11. Pruebas de aceptación

Priorizar pruebas de integración que recorran los endpoints y comprueben los cambios de estado. Las pruebas de la cadena completa no reemplazarán la base de datos, el adaptador o la descarga por respuestas simuladas.

### Operaciones legítimas

- El cliente consulta su ticket propio y no accede al buscador ni a la descarga, incluso con A10 habilitada.
- La recuperación de la propia cuenta funciona. Un token inválido, vencido o consumido se rechaza en ambos modos.
- El buzón local nunca muestra mensajes de otra cuenta.
- El operador busca y descarga una exportación general de B; con contexto válido recibe 403 para una confidencial.
- El supervisor obtiene el CSV confidencial con contexto válido en ambos modos.
- El cierre de sesión revoca la sesión en el servidor.

### Cadena y correcciones aisladas

| Configuración | Resultado esperado |
| --- | --- |
| Las cuatro fallas habilitadas | T1 obtiene la identidad; T2 consigue la cuenta; T3 obtiene el UUID; T4 descarga el CSV con el marcador esperado. |
| Solo A01 corregida | T1 obtiene 403 al pedir el ticket ajeno y no revela al operador. |
| Solo A07 corregida | T2 obtiene 400; la contraseña del operador permanece sin cambios. |
| Solo A05 corregida | La entrada de T3 se trata como texto y no devuelve el UUID confidencial. |
| Solo A10 corregida | Para la sesión y el UUID obtenidos, contexto válido da 403 y `context: null` da 400; ninguno entrega el CSV. |
| Todas corregidas | La cadena no progresa desde T1 y las operaciones legítimas continúan funcionando. |

Para comprobar una etapa aislada pueden prepararse cuentas y recursos desde fixtures. En el ensayo completo, el actor atacante solo utilizará sus credenciales iniciales y datos extraídos de las respuestas anteriores. No leerá la base de datos ni un archivo de credenciales para saltar pasos.

Comprobar además que el catálogo no devuelve el marcador del CSV, que un UUID desconocido produce 404 y que una excepción inesperada del adaptador corregido produce 503 sin contenido del archivo. Esta última prueba puede inducir el error desde el test; el disparador de la demostración seguirá siendo el campo `context`.

## 12. Guion de demostración y evidencias

`scripts/demo_chain.py` deberá aceptar una URL local del laboratorio y credenciales del cliente. Mantendrá las cookies y CSRF de cada sesión, leerá el buzón propio, extraerá la identidad del operador de T1 y extraerá el UUID confidencial de T3. Abrirá una sesión nueva para el operador después del restablecimiento.

El guion registrará la secuencia y se detendrá con una explicación si falla una precondición. No tendrá credenciales de operador o supervisor como entrada, ni UUID confidenciales hardcodeados. Limitar su destino a la instancia local de desarrollo.

Guardar evidencias locales con método, ruta, estado HTTP, identidad utilizada y resultado relevante. Para T4, conservar ambas respuestas y verificar el marcador en el CSV descargado. Evitar guardar contraseñas, cookies y tokens completos en los informes o en Git; se regenerarán en cada ensayo.

En `docs/demo.md`, documentar los payloads realmente verificados, las respuestas esperadas y las obtenidas, la explicación de cada causa y la repetición con las correcciones. Las capturas y pruebas solo se marcarán como realizadas después de ejecutarlas.

## 13. Orden de desarrollo

1. **Inspección y base del proyecto.** Revisar repositorio e instrucciones locales, crear la fábrica Flask, fijar dependencias y agregar Docker Compose, configuración y `/health`.
2. **Semilla y comportamiento legítimo.** Implementar persistencia, cuentas, sesiones, buzón, recuperación, tickets, buscador y permisos con las cuatro fallas deshabilitadas. Verificar los casos normales.
3. **Fallas intencionales.** Incorporar cada variante vulnerable detrás de su opción de configuración y comprobar el cambio de comportamiento de T1 a T4. No reemplazar las fallas por respuestas precalculadas.
4. **Demostración completa.** Implementar el guion HTTP, validar que descubra los datos etapa por etapa y ejecutar las correcciones aisladas.
5. **Interfaz y documentación.** Completar las pantallas necesarias, revisar la demostración con navegador y Burp y documentar arranque, reinicio, pruebas y evidencias.

Como contrato de uso, el proyecto terminado deberá ofrecer estos comandos; hoy son objetivos de implementación:

```bash
docker compose up --build -d
docker compose exec web flask --app app lab reset
docker compose exec web pytest -q
docker compose down
```

Definir el arranque para inicializar una semilla si no hay datos, sin reiniciar ni sobrescribir datos existentes. El reinicio explícito se hará sin peticiones activas. Incluir las dependencias de prueba necesarias para que el comando `pytest` funcione en el entorno de laboratorio.

Documentar cómo copiar `.env.example` a `.env` y cómo ejecutar el guion HTTP. No depender de `make` o de scripts Bash exclusivos para las operaciones básicas: el entorno de escritorio puede usar Windows y Docker Desktop.

## 14. Criterio de finalización del desarrollo

El laboratorio estará listo cuando arranque desde un checkout limpio, tenga las operaciones legítimas implementadas, reproduzca T1 a T4 contra la aplicación real, descargue el CSV únicamente en la condición prevista y muestre que cada corrección corta su etapa. También deberán existir un reinicio reproducible, pruebas ejecutables y una guía que otra persona pueda seguir.

Al informar el avance, indicar qué se implementó, qué comandos y pruebas se ejecutaron y qué limitaciones se observaron. Conservar esta distinción durante todo el desarrollo.

## 15. Documentos y referencias

- Documento de alcance ya redactado: `Entrega_preliminar_TP_Seguridad_Web_Exportaciones_confidenciales.docx`. Puede copiarse a `docs/` junto con este handover; no es necesario volver a elegir entre alternativas.
- Material de la cátedra: `Seg App Web - OWASP Top Ten 2026 v1C 2026.pdf`. A01: páginas 13-18; A07: 83-87; A05: 61-68; A10: 98-101, según su posición en el PDF.
- Clasificación oficial: [A01 Broken Access Control](https://top10.owasp.org/2025/A01_2025-Broken_Access_Control/), [A07 Authentication Failures](https://top10.owasp.org/2025/A07_2025-Authentication_Failures/), [A05 Injection](https://top10.owasp.org/2025/A05_2025-Injection/) y [A10 Mishandling of Exceptional Conditions](https://top10.owasp.org/2025/A10_2025-Mishandling_of_Exceptional_Conditions/).
- Recuperación de cuentas: [OWASP Forgot Password Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Forgot_Password_Cheat_Sheet.html).

Las rutas de proyecto de este archivo son relativas a la carpeta que se abra en Codex Desktop. No dependen de rutas temporales ni de identificadores internos de la conversación anterior.
