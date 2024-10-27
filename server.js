const express = require('express');
const mysql = require('mysql');
const bodyParser = require('body-parser');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const xlsx = require('xlsx'); // Paquete para leer archivos Excel
const nodemailer = require('nodemailer'); // Paquete para enviar correos electrónicos
const jwt = require('jsonwebtoken'); // Si estás usando JSON Web Tokens (JWT) para manejar la autenticación
const secretKey = 'your_secret_key'; // Cambia esto a una clave secreta más segura
const fs = require('fs'); // Importa el módulo 'fs'

const app = express();
app.use(bodyParser.json());
app.use(cors());

// Configuración de Multer para almacenamiento en diferentes directorios
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    // Determina el directorio de destino basado en la ruta de la solicitud
    if (req.path === '/upload') {
      cb(null, path.join(__dirname, 'uploads'));
    } else if (req.path === '/upload-attendance') {
      cb(null, path.join(__dirname, 'uploadss'));
    } else if (req.path === '/upload-eva') {
      cb(null, path.join(__dirname, 'uploadsss'));
    }  else {
      cb(new Error('Ruta no soportada'));
    }
  },
  filename: function (req, file, cb) {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({ storage: storage });



// Configuración de conexión a MySQL
const db = mysql.createConnection({
  host: 'colegiodb.c9ys8ig6opqq.us-east-2.rds.amazonaws.com',
  user: 'admin',        // Reemplaza con tu usuario de MySQL
  password: '3105084629',   // Reemplaza con tu contraseña de MySQL
  database: 'colegio_db',
  port: 3306
});

db.connect(err => {
  if (err) {
    console.error('Error al conectar a la base de datos:', err);
    return;
  }
  console.log('MySQL conectado...');
});

// Configuración de Nodemailer
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: 'iesfa024@gmail.com', // Tu correo electrónico
    pass: 'cggb kcvn zjnc nvta',   // Tu contraseña de correo electrónico o App Password
  },
});

// Función para enviar correos electrónicos
const sendEmail = async (to, subject, text) => {
  try {
    await transporter.sendMail({
      from: 'iesfa024@gmail.com',
      to: to,
      subject: subject,
      text: text,
    });
    console.log(`Correo enviado exitosamente a: ${to}`);
  } catch (error) {
    console.error('Error al enviar el correo:', error);
    throw new Error(`Error al enviar correo a ${to}: ${error.message}`); // Lanza un error con información detallada
  }
};


// Ruta para enviar correos electrónicos a estudiantes ausentes
app.post('/send-absent-emails', async (req, res) => {
  const { course, absent_students } = req.body;

  if (!course) {
    return res.status(400).json({ success: false, message: 'El curso es requerido' });
  }
  if (!absent_students || !Array.isArray(absent_students)) {
    return res.status(400).json({ success: false, message: 'Se requieren estudiantes ausentes' });
  }

  // Obtener el contenido del archivo de asistencias para el curso especificado
  const query = 'SELECT contenido FROM archivos_asistencias WHERE curso = ? ORDER BY fecha_subida DESC LIMIT 1';
  db.query(query, [course], async (err, results) => {
    if (err) {
      console.error('Error al consultar la base de datos:', err);
      return res.status(500).json({ success: false, message: 'Error del servidor' });
    }
    if (results.length === 0) {
      return res.status(404).json({ success: false, message: 'Archivo no encontrado para el curso' });
    }

    try {
      const content = JSON.parse(results[0].contenido);

      // Imprimir el contenido y los estudiantes ausentes para depuración
      console.log('Contenido del archivo:', content);
      console.log('Estudiantes ausentes:', absent_students);

      const absentEmails = content
        .filter(item => {
          const studentId = item['id']?.toString();
          return studentId && absent_students.includes(studentId) && item['Correo Electrónico']; // Verifica que haya correo
        })
        .map(item => item['Correo Electrónico']?.toString() ?? ''); // Obtener correos electrónicos

      if (absentEmails.length === 0) {
        return res.json({ success: true, message: 'No hay correos electrónicos válidos para enviar' });
      }

      // Enviar correos electrónicos a los estudiantes ausentes
      for (const email of absentEmails) {
        if (email) {
          await sendEmail(email, 'Asistencia', 'No asististe a la clase. Por favor, acercarse donde el coordinador de convivencia o director de curso.');
        }
      }
      res.json({ success: true, message: 'Correos electrónicos enviados exitosamente' });
    } catch (e) {
      console.error('Error al parsear el contenido:', e);
      res.status(500).json({ success: false, message: 'Error al parsear el contenido del archivo' });
    }
  });
});



app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const query = 'SELECT * FROM users WHERE username = ? AND password = ?';

  db.query(query, [username, password], (err, result) => {
    if (err) {
      console.error('Error al consultar la base de datos:', err);
      res.status(500).json({ success: false, message: 'Error del servidor' });
      return;
    }
    if (result.length > 0) {
      const user = result[0];
      // Asegúrate de que la clave secreta aquí coincida con la usada para la verificación
      const token = jwt.sign({ id: user.id, username: user.username }, 'tu_secreto', { expiresIn: '1h' });
      res.json({ success: true, token: token });
    } else {
      res.json({ success: false, message: 'Credenciales incorrectas' });
    }
  });
});


// Ruta de registro
app.post('/register', (req, res) => {
  const { username, password } = req.body;

  // Validar que el nombre de usuario y la contraseña no estén vacíos
  if (!username || !password) {
    return res.status(400).json({ success: false, message: 'Nombre de usuario y contraseña son requeridos' });
  }

  // Verificar si el usuario ya existe
  const checkQuery = 'SELECT * FROM users WHERE username = ?';
  db.query(checkQuery, [username], (err, result) => {
    if (err) {
      console.error('Error al consultar la base de datos:', err);
      return res.status(500).json({ success: false, message: 'Error del servidor' });
    }
    if (result.length > 0) {
      return res.status(400).json({ success: false, message: 'El usuario ya existe' });
    }

    // Insertar el nuevo usuario
    const insertQuery = 'INSERT INTO users (username, password) VALUES (?, ?)';
    db.query(insertQuery, [username, password], (err) => {
      if (err) {
        console.error('Error al insertar en la base de datos:', err);
        return res.status(500).json({ success: false, message: 'Error del servidor' });
      }
      res.json({ success: true });
    });
  });
});

// Ruta de inicio de sesión de admin
app.post('/loginadmin', (req, res) => {
  const { username, password } = req.body;
  const query = 'SELECT * FROM admins WHERE username = ? AND password = ?';
  db.query(query, [username, password], (err, result) => {
    if (err) {
      console.error('Error al consultar la base de datos:', err);
      res.status(500).json({ success: false, message: 'Error del servidor' });
      return;
    }
    if (result.length > 0) {
      res.json({ success: true });
    } else {
      res.json({ success: false });
    }
  });
});

// Ruta de inicio de sesión de asistencia
app.post('/loginasistencia', (req, res) => {
  const { username, password } = req.body;
  const query = 'SELECT * FROM profesores WHERE username = ? AND password = ?';
  db.query(query, [username, password], (err, result) => {
    if (err) {
      console.error('Error al consultar la base de datos:', err);
      res.status(500).json({ success: false, message: 'Error del servidor' });
      return;
    }
    if (result.length > 0) {
      res.json({ success: true });
    } else {
      res.json({ success: false });
    }
  });
});

app.get('/user-grades/:token', (req, res) => {
  const token = req.params.token;
  const year = req.query.year;
  const period = req.query.period;
  const tipo = req.query.tipo;  // 'institucion' o 'eva'

  console.log('Token:', token);
  console.log('Year:', year);
  console.log('Period:', period);
  console.log('Tipo:', tipo);

  try {
    // Verificar el token
    const decoded = jwt.verify(token, 'tu_secreto');
    console.log('Decoded Token:', decoded);

    if (!tipo || !['institucion', 'eva'].includes(tipo)) {
      return res.status(400).json({ success: false, message: 'Tipo de consulta no válido' });
    }

    // Variables para consulta
    let query;
    let params = [decoded.username];

    // Definir consulta según tipo
    if (tipo === 'institucion') {
      query = `
        SELECT contenido
        FROM archivos
        WHERE JSON_CONTAINS(
          JSON_EXTRACT(contenido, '$[*].Documento'),
          CAST(? AS UNSIGNED),
          '$'
        )`;

      // Añadir año y período si existen
      if (year) {
        query += ` AND año = ?`;
        params.push(year);
      }
      if (period) {
        query += ` AND periodos = ?`;
        params.push(period);
      }
    } else if (tipo === 'eva') {
      query = `
        SELECT contenido
        FROM archivoseva
        WHERE JSON_CONTAINS(
          JSON_EXTRACT(contenido, '$[*].Documento'),
          CAST(? AS UNSIGNED),
          '$'
        )`;

      // Añadir año si existe (en 'eva' no se requiere periodo)
      if (year) {
        query += ` AND año = ?`;
        params.push(year);
      }
    }

    console.log('Query:', query);
    console.log('Params:', params);

    // Ejecutar consulta según el tipo seleccionado
    db.query(query, params, (error, results) => {
      if (error) {
        console.error('Database Query Error:', error); // Log de error
        return res.status(500).json({ success: false, message: 'Error al consultar la base de datos' });
      }

      // Log de resultados
      console.log('Query Results:', results);

      // Verificar si hay resultados y extraer contenido
      const content = results.length > 0
        ? JSON.parse(results[0].contenido.toString('utf-8')).find(entry => entry.Documento === Number(decoded.username))
        : null;

      // Responder con los datos obtenidos o un mensaje si no hay contenido
      res.json({
        success: true,
        content: content || `No hay calificaciones en la tabla ${tipo === 'institucion' ? 'archivos' : 'archivoseva'}`,
      });
    });
  } catch (err) {
    console.error('Token Error:', err); // Log de error
    res.status(401).json({ success: false, message: 'Token inválido o expirado' });
  }
});


// Ruta para obtener la lista de usuarios
app.get('/users', (req, res) => {
  const query = 'SELECT username, password FROM users';
  db.query(query, (err, results) => {
    if (err) {
      console.error('Error al consultar la base de datos:', err);
      return res.status(500).json({ success: false, message: 'Error del servidor' });
    }
    res.json({ success: true, users: results });
  });
});

// Ruta para editar un usuario
app.put('/users/:username', (req, res) => {
  const { username } = req.params;
  const { newUsername, password } = req.body;

  if (!password) {
    return res.status(400).json({ success: false, message: 'La contraseña es requerida' });
  }

  let query;
  const queryParams = [];

  if (newUsername) {
    // Check if the new username already exists
    db.query('SELECT * FROM users WHERE username = ?', [newUsername], (err, results) => {
      if (err) {
        console.error('Error al verificar el nuevo nombre de usuario:', err);
        return res.status(500).json({ success: false, message: 'Error del servidor' });
      }

      if (results.length > 0) {
        return res.status(400).json({ success: false, message: 'El nuevo nombre de usuario ya existe' });
      }

      // Update both username and password
      query = 'UPDATE users SET username = ?, password = ? WHERE username = ?';
      queryParams.push(newUsername, password, username);
      
      db.query(query, queryParams, (err, results) => {
        if (err) {
          console.error('Error al actualizar el usuario:', err);
          return res.status(500).json({ success: false, message: 'Error del servidor' });
        }

        if (results.affectedRows === 0) {
          return res.status(404).json({ success: false, message: 'Usuario no encontrado' });
        }

        res.json({ success: true });
      });
    });
  } else {
    // Update only password
    query = 'UPDATE users SET password = ? WHERE username = ?';
    queryParams.push(password, username);

    db.query(query, queryParams, (err, results) => {
      if (err) {
        console.error('Error al actualizar el usuario:', err);
        return res.status(500).json({ success: false, message: 'Error del servidor' });
      }

      if (results.affectedRows === 0) {
        return res.status(404).json({ success: false, message: 'Usuario no encontrado' });
      }

      res.json({ success: true });
    });
  }
});

// Ruta para eliminar un usuario
app.delete('/users/:username', (req, res) => {
  const { username } = req.params;

  const query = 'DELETE FROM users WHERE username = ?';
  db.query(query, [username], (err) => {
    if (err) {
      console.error('Error al eliminar el usuario:', err);
      return res.status(500).json({ success: false, message: 'Error del servidor' });
    }
    res.json({ success: true });
  });
});

// Ruta para subir archivo Excel de general
app.post('/upload', upload.single('file'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ success: false, message: 'No se ha subido ningún archivo' });
  }

  const course = req.body.course;
  const year = req.body.year;     // Año seleccionado
  const period = req.body.period; // Período seleccionado

  // Leer el archivo Excel
  const filePath = path.join(__dirname, 'uploads', req.file.filename);
  const workbook = xlsx.readFile(filePath);
  const sheetName = workbook.SheetNames[0];
  const sheet = workbook.Sheets[sheetName];
  const data = xlsx.utils.sheet_to_json(sheet);

  // Convertir el contenido del archivo a una cadena
  const content = JSON.stringify(data);

  // Guardar la información en la base de datos con los campos adicionales año y periodo
  const query = 'INSERT INTO archivos (curso, nombre_archivo, contenido, fecha_subida, año, periodos) VALUES (?, ?, ?, NOW(), ?, ?)';
  db.query(query, [course, req.file.filename, content, year, period], async (err) => {
    if (err) {
      console.error('Error al insertar en la base de datos:', err);
      return res.status(500).json({ success: false, message: 'Error del servidor' });
    }

    // Enviar el correo electrónico con la información adicional del año y periodo
    await sendEmail('santiago6797@live.com', 'Archivo Subido', `Se ha subido un nuevo archivo para el curso ${course} del año ${year}, período ${period}.`);

    res.json({ success: true, message: 'Archivo subido exitosamente' });
  });
});


// Ruta para subir archivo Excel de asistencias
app.post('/upload-attendance', upload.single('file'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ success: false, message: 'No se ha subido ningún archivo' });
  }
  const course = req.body.course;

  // Leer el archivo Excel
  const filePath = path.join(__dirname, 'uploadss', req.file.filename);
  const workbook = xlsx.readFile(filePath);
  const sheetName = workbook.SheetNames[0];
  const sheet = workbook.Sheets[sheetName];
  const data = xlsx.utils.sheet_to_json(sheet);

  // Convertir el contenido del archivo a una cadena
  const content = JSON.stringify(data);

  // Guardar la información en la base de datos
  const query = 'INSERT INTO archivos_asistencias (curso, nombre_archivo, contenido, fecha_subida) VALUES (?, ?, ?, NOW())';
  db.query(query, [course, req.file.filename, content], async (err) => {
    if (err) {
      console.error('Error al insertar en la base de datos:', err);
      return res.status(500).json({ success: false, message: 'Error del servidor' });
    }

    // Enviar el correo electrónico
    await sendEmail('santiago6797@live.com', 'Archivo Subido', `Se ha subido un nuevo archivo para el curso ${course}.`);

    res.json({ success: true, message: 'Archivo subido exitosamente' });
  });
});

// Ruta para subir archivo Excel de notas eva
app.post('/upload-eva', upload.single('file'), async (req, res) => {
  if (!req.file) {
    return res.status(400).json({ success: false, message: 'No se ha subido ningún archivo' });
  }

  const course = req.body.course;
  const year = req.body.year; // Añadir el año

  // Leer el archivo Excel
  const filePath = path.join(__dirname, 'uploadsss', req.file.filename);
  const workbook = xlsx.readFile(filePath);
  const sheetName = workbook.SheetNames[0];
  const sheet = workbook.Sheets[sheetName];
  const data = xlsx.utils.sheet_to_json(sheet);

  // Convertir el contenido del archivo a una cadena
  const content = JSON.stringify(data);

  // Guardar la información en la base de datos sin el campo de períodos
  const query = 'INSERT INTO archivoseva (curso, nombre_archivo, contenido, año, fechasubida) VALUES (?, ?, ?, ?, NOW())';
  db.query(query, [course, req.file.filename, content, year], async (err) => {
    if (err) {
      console.error('Error al insertar en la base de datos:', err);
      return res.status(500).json({ success: false, message: 'Error del servidor' });
    }

    // Enviar el correo electrónico
    await sendEmail('santiago6797@live.com', 'Archivo Subido', `Se ha subido un nuevo archivo para el curso ${course}, año ${year}.`);

    res.json({ success: true, message: 'Archivo subido exitosamente' });
  });
});



// Ruta para obtener los cursos disponibles para general
app.get('/courses', (req, res) => {
  const query = 'SELECT DISTINCT curso FROM archivos';
  db.query(query, (err, results) => {
    if (err) {
      console.error('Error al consultar la base de datos:', err);
      return res.status(500).json({ success: false, message: 'Error del servidor' });
    }
    res.json({ success: true, courses: results.map(row => row.curso) });
  });
});

// Ruta para obtener los cursos disponibles de asistencias
app.get('/courses-attendance', (req, res) => {
  const query = 'SELECT DISTINCT curso FROM archivos_asistencias';
  db.query(query, (err, results) => {
    if (err) {
      console.error('Error al consultar la base de datos:', err);
      return res.status(500).json({ success: false, message: 'Error del servidor' });
    }
    res.json({ success: true, courses: results.map(row => row.curso) });
  });
});

app.get('/file-content/:course/:year/:period', (req, res) => {
  const { course, year, period } = req.params;

  // Modificar la consulta para incluir curso, año y periodo
  const query = `
    SELECT contenido 
    FROM archivos 
    WHERE curso = ? AND año = ? AND periodos = ? 
    ORDER BY fecha_subida DESC 
    LIMIT 1`;

  // Ejecutar la consulta con los parámetros curso, año y periodo
  db.query(query, [course, year, period], (err, results) => {
    if (err) {
      console.error('Error al consultar la base de datos:', err);
      return res.status(500).json({ success: false, message: 'Error del servidor' });
    }
    
    if (results.length === 0) {
      return res.status(404).json({ success: false, message: 'Archivo no encontrado para el curso, año o periodo' });
    }
    
    try {
      const content = JSON.parse(results[0].contenido);
      res.json({ success: true, content });
    } catch (e) {
      console.error('Error al parsear el contenido:', e);
      res.status(500).json({ success: false, message: 'Error al parsear el contenido del archivo' });
    }
  });
});


// Ruta para obtener el contenido del archivo Excel para un curso específico de asistencias
app.get('/file-content-attendance/:course', (req, res) => {
  const { course } = req.params; // Usa 'course' para que coincida con la ruta
  const query = 'SELECT contenido FROM archivos_asistencias WHERE curso = ? ORDER BY fecha_subida DESC LIMIT 1';
  db.query(query, [course], (err, results) => {
    if (err) {
      console.error('Error al consultar la base de datos:', err);
      return res.status(500).json({ success: false, message: 'Error del servidor' });
    }
    if (results.length === 0) {
      return res.status(404).json({ success: false, message: 'Archivo no encontrado para el curso' });
    }
    try {
      const content = JSON.parse(results[0].contenido);
      res.json({ success: true, content });
    } catch (e) {
      console.error('Error al parsear el contenido:', e);
      res.status(500).json({ success: false, message: 'Error al parsear el contenido del archivo' });
    }
  });
});

// Ruta para listar archivos de ambos tipos (generales y asistencias)
app.get('/list-files', (req, res) => {
  const query = `
    SELECT curso, nombre_archivo, 'general' AS tipo FROM archivos
    UNION ALL
    SELECT curso, nombre_archivo, 'asistencia' AS tipo FROM archivos_asistencias
    UNION ALL
    SELECT curso, nombre_archivo, 'pruebaseva' AS tipo FROM archivoseva
  `;

  db.query(query, (err, results) => {
    if (err) {
      console.error('Error al consultar la base de datos:', err);
      return res.status(500).json({ success: false, message: 'Error del servidor' });
    }

    res.json({ success: true, files: results });
  });
});

// Ruta para eliminar un archivo
app.delete('/delete-file/:tipo/:nombre', (req, res) => {
  const tipo = req.params.tipo.toLowerCase(); // Asegurarse de que sea en minúsculas
  const nombreArchivo = req.params.nombre;

  // Verificar a qué tabla pertenece el archivo según el tipo
  let query = '';
  let fileDirectory = '';

  if (tipo === 'general') {
    query = 'DELETE FROM archivos WHERE nombre_archivo = ?';
    fileDirectory = path.join(__dirname, 'uploads');
  } else if (tipo === 'asistencia') {
    query = 'DELETE FROM archivos_asistencias WHERE nombre_archivo = ?';
    fileDirectory = path.join(__dirname, 'uploadss');
  } else if (tipo === 'pruebaseva') {
    query = 'DELETE FROM archivoseva WHERE nombre_archivo = ?';
    fileDirectory = path.join(__dirname, 'uploadsss');
  } else {
    return res.status(400).json({ success: false, message: 'Tipo de archivo no válido' });
  }

  // Eliminar el registro en la base de datos
  db.query(query, [nombreArchivo], (err) => {
    if (err) {
      console.error('Error al eliminar de la base de datos:', err);
      return res.status(500).json({ success: false, message: 'Error del servidor' });
    }

    // Eliminar el archivo del sistema de archivos desde el directorio adecuado
    const filePath = path.join(fileDirectory, nombreArchivo);
    console.log('Ruta del archivo:', filePath); // Verificar la ruta del archivo

    if (fs.existsSync(filePath)) {
      fs.unlink(filePath, (err) => {
        if (err) {
          console.error('Error al eliminar el archivo del sistema:', err);
          return res.status(500).json({ success: false, message: 'Error al eliminar el archivo del servidor' });
        }

        res.json({ success: true, message: 'Archivo eliminado exitosamente' });
      });
    } else {
      console.error('Archivo no encontrado:', filePath);
      return res.status(404).json({ success: false, message: 'Archivo no encontrado' });
    }
  });
});



// Configura el puerto para el servidor Express (diferente del puerto de MySQL)
const PORT = process.env.PORT || 80; // Usa un puerto diferente a 3307
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Servidor corriendo en el puerto ${PORT}`);
});
