// server.js - Backend Express xử lý đăng nhập
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
const PORT = 3000;

// Fake user database
const users = [
  {
    username: 'techuser',
    password: '123456',
  },
];

app.use(cors());
app.use(bodyParser.json());

// Đăng nhập (kiểm tra username/password)
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username && u.password === password);

  if (user) {
    res.json({ success: true, message: 'Đăng nhập thành công!' });
  } else {
    res.status(401).json({ success: false, message: 'Sai tên đăng nhập hoặc mật khẩu.' });
  }
});

app.listen(PORT, () => {
  console.log(`Server đang chạy tại http://localhost:${PORT}`);
});
