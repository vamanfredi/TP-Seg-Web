# Laboratorio de seguridad web

## Recuperación de contraseña

1. Levantá el portal y el buzón con `docker compose up -d --build`.
2. En el [portal](http://127.0.0.1:8000/?view=recovery), solicitá la recuperación con tu usuario.
3. Ingresá al [buzón de pruebas](http://127.0.0.1:8025/) con `cliente.a` y la contraseña de demostración `BuzonA-2026!`.
4. Abrí **Restablecer contraseña** en el mensaje y elegí una contraseña nueva. El enlace lleva los datos de la solicitud y vence a los 10 minutos por defecto.

Para elegir otra contraseña del buzón de `cliente.a`, configurá `LAB_DEFAULT_MAILBOX_PASSWORD` en `.env` y ejecutá `docker compose up -d --build`. Debe tener al menos 12 caracteres. Con `LAB_DEFAULT_MAILBOX_PASSWORD=` vacío, el buzón usa una contraseña generada para esa cuenta.

Consultá las credenciales con `docker compose exec web flask --app app lab mailbox-credentials`. Agregá `--developer` para incluir operador y supervisor, que usan contraseñas generadas. Un `lab reset` renueva las credenciales generadas.

Sin Docker, usá el mismo `APP_DATA_DIR` para el portal (`python -m app`) y el buzón (`python -m app.mailbox` en otra terminal). Consultá la contraseña del buzón con `flask --app app lab mailbox-credentials`.

`PORTAL_URL` y `MAILBOX_URL` configuran los orígenes de los enlaces. La API `/lab/inbox` se mantiene para los scripts de la demostración A07.

## Contraseña del cliente en Docker

El usuario `cliente.a` usa por defecto la contraseña local de demostración `ClienteA-2026!`.
Al arrancar el servidor (`python -m app`), se restaura esa contraseña aunque ya exista el volumen de datos.
Si la contraseña cambió, se invalidan las sesiones y los tokens de recuperación del cliente.
Los demás usuarios, tickets y exportaciones se conservan.

Para aplicar cambios de código o configuración:

```sh
docker compose up -d --build
```

Los siguientes reinicios también restauran la contraseña configurada:

```sh
docker compose restart web
```

Para elegir otra contraseña, agregá `LAB_DEFAULT_CLIENT_PASSWORD=Tu-Clave-De-Demo-2026` a `.env`
y ejecutá `docker compose up -d --build`. Debe tener al menos 12 caracteres.
Con `LAB_DEFAULT_CLIENT_PASSWORD=` vacío se desactiva la restauración y las nuevas semillas usan una contraseña aleatoria.
Sin Docker, la restauración está desactivada salvo que se configure esa variable.

`flask --app app lab credentials` permite consultar las credenciales de la semilla sin restaurar la contraseña.
Si se cambia mediante recuperación, ese archivo conserva la contraseña de la semilla hasta el próximo arranque del servidor.
`flask --app app lab reset` recrea todos los datos del laboratorio y utiliza la contraseña configurada para el cliente.
