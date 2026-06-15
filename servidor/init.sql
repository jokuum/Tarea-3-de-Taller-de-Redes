CREATE DATABASE IF NOT EXISTS taller_redes
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

CREATE USER IF NOT EXISTS 'usuario'@'%' IDENTIFIED BY 'usuario_password';

GRANT ALL PRIVILEGES ON taller_redes.* TO 'usuario'@'%';

FLUSH PRIVILEGES;
