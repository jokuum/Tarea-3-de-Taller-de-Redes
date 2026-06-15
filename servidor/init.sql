-- Crear la base de datos con codificación UTF-8 completa
CREATE DATABASE IF NOT EXISTS taller_redes
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

-- Crear el usuario que puede conectarse desde CUALQUIER host (el '%' es el comodín)
CREATE USER IF NOT EXISTS 'usuario'@'%' IDENTIFIED BY 'usuario_password';

-- Otorgar todos los privilegios sobre la base de datos taller_redes
GRANT ALL PRIVILEGES ON taller_redes.* TO 'usuario'@'%';

-- Recargar la tabla de permisos en memoria para que los cambios surtan efecto
FLUSH PRIVILEGES;
