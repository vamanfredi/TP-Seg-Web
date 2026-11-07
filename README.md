# Laboratorio de seguridad web

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
