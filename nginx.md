# Asegurar nginx

Esta es una guía breve para añadir cabeceras de seguridad recomendadas en un servidor **nginx**.

Recurso general: https://webdock.io/en/docs/how-guides/security-guides/how-to-configure-security-headers-in-nginx-and-apache

---

### Desactivar los *server tokens* (ocultar versión)

Documentación: https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens

```nginx
server_tokens off;
```

Con esto nginx dejará de mostrar su versión en las respuestas y en las páginas de error, lo que reduce la información expuesta.

---

### Política de Seguridad de Contenidos (CSP)

Más info: https://content-security-policy.com/

```nginx
add_header Content-Security-Policy "default-src 'self';" always;
```

Ajusta la política según lo que sirva tu sitio (scripts externos, fuentes, imágenes, etc.).

---

### X-Frame-Options (proteger contra clickjacking)

Documentación: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options#sameorigin

```nginx
add_header X-Frame-Options SAMEORIGIN always;
```

Evita que tu sitio se cargue dentro de un `<iframe>` de otro dominio.

---

### X-XSS-Protection (protección básica XSS)

Documentación: https://docs.nginx.com/nginx-management-suite/acm/how-to/policies/proxy-response-headers/

```nginx
add_header X-Xss-Protection "1; mode=block" always;
```

Activa la protección básica de XSS en navegadores que aún la soportan.

---

### Política de Referer (Referrer-Policy)

Documentación: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy#strict-origin

```nginx
add_header Referrer-Policy "strict-origin" always;
```

Controla qué información de referencia envía el navegador al navegar desde tu sitio.

---

### Política de Permisos (Permissions-Policy)

Documentación: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy

```nginx
add_header Permissions-Policy "geolocation=(),midi=(),sync-xhr=(),microphone=(),camera=(),magnetometer=(),gyroscope=(),fullscreen=(self),payment=()";
```

Con esto desactivas por defecto muchas APIs del navegador que tu sitio probablemente no necesita.

---

### Evitar la detección del tipo de contenido (*content sniffing*)

Más info: https://es.wikipedia.org/wiki/Rastreo_de_contenido

```nginx
add_header X-Content-Type-Options nosniff always;
```

Evita que el navegador intente “adivinar” el tipo de contenido, lo que puede abrir la puerta a ataques.

---

### Dónde poner estas directivas

Puedes poner estas líneas:

- En el bloque `server { ... }` si solo quieres que se apliquen a un sitio.
- En el bloque `http { ... }` si quieres aplicarlas a todos los sitios.

Recuerda recargar nginx después de los cambios:

```bash
sudo nginx -t
sudo systemctl reload nginx
```
