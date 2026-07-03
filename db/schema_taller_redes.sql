CREATE TABLE usuarios (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(50) NOT NULL UNIQUE,
  email VARCHAR(100) NOT NULL UNIQUE,
  fecha_registro DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE posts (
  id INT AUTO_INCREMENT PRIMARY KEY,
  usuario_id INT NOT NULL,
  contenido TEXT NOT NULL,
  fecha DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
);
CREATE TABLE comentarios (
  id INT AUTO_INCREMENT PRIMARY KEY,
  post_id INT NOT NULL,
  usuario_id INT NOT NULL,
  texto TEXT NOT NULL,
  fecha DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (post_id) REFERENCES posts(id),
  FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
);
CREATE TABLE likes (
  id INT AUTO_INCREMENT PRIMARY KEY,
  post_id INT NOT NULL,
  usuario_id INT NOT NULL,
  UNIQUE KEY unico_like (post_id, usuario_id),
  FOREIGN KEY (post_id) REFERENCES posts(id),
  FOREIGN KEY (usuario_id) REFERENCES usuarios(id)
);
INSERT INTO usuarios (username, email) VALUES
  ('ana_gomez', 'ana@example.com'),
  ('luis_perez', 'luis@example.com'),
  ('maria_silva', 'maria@example.com'),
  ('carlos_rojo', 'carlos@example.com'),
  ('sofia_luna', 'sofia@example.com');
INSERT INTO posts (usuario_id, contenido) VALUES
  (1, 'Acabo de ver el partido, tremendo golazo en el último minuto!'),
  (2, 'Recomendación de película: Interestelar, la mejor que he visto este año.'),
  (3, 'Alguien sabe de algún buen restaurante cerca del centro?'),
  (4, 'Fin de semana largo, por fin puedo descansar un poco.'),
  (5, 'Empezando el gym hoy, a ver cuánto duro jaja.'),
  (1, 'Increíble concierto anoche, la banda estuvo espectacular.'),
  (2, 'Tip del día: tomar agua antes del café mejora mucho la energía.');
INSERT INTO comentarios (post_id, usuario_id, texto) VALUES
  (1, 2, 'Yo también lo vi, no lo podía creer!'),
  (1, 3, 'Qué equipos jugaban?'),
  (2, 1, 'Interestelar es un clásico, totalmente de acuerdo.'),
  (3, 4, 'Hay un italiano muy bueno en la calle principal.'),
  (3, 5, 'El restaurante del mercado central está muy bien.'),
  (4, 1, 'Aprovecha para dormir bien!'),
  (5, 2, 'Ánimo, el primer día siempre es el más difícil.'),
  (6, 3, 'Cuál banda fue? Me muero de envidia!'),
  (7, 4, 'Voy a probar ese tip mañana, gracias.');
INSERT INTO likes (post_id, usuario_id) VALUES
  (1, 2), (1, 3), (1, 4),
  (2, 1), (2, 5),
  (3, 1), (3, 2), (3, 5),
  (4, 3), (4, 5),
  (5, 1), (5, 3),
  (6, 2), (6, 4), (6, 5),
  (7, 1), (7, 3);
SELECT * FROM usuarios;
SELECT p.id, u.username, p.contenido, p.fecha
FROM posts p
JOIN usuarios u ON p.usuario_id = u.id
ORDER BY p.fecha DESC;
SELECT c.id, u.username, p.contenido AS post, c.texto, c.fecha
FROM comentarios c
JOIN usuarios u ON c.usuario_id = u.id
JOIN posts p ON c.post_id = p.id;
SELECT p.id, p.contenido, COUNT(l.id) AS total_likes
FROM posts p
LEFT JOIN likes l ON p.id = l.post_id
GROUP BY p.id
ORDER BY total_likes DESC;
UPDATE usuarios SET email = 'ana_nueva@example.com' WHERE id = 1;
UPDATE posts SET contenido = 'Increíble concierto anoche, la banda tocó todos sus clásicos!' WHERE id = 6;
DELETE FROM likes WHERE post_id = 1 AND usuario_id = 4;
DELETE FROM comentarios WHERE id = 9;
SELECT * FROM usuarios;
SELECT * FROM posts;
