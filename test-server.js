const express = require('express');
const app = express();
const PORT = 3001;

app.use(express.json());

app.get('/', (req, res) => {
  res.send('Hello World!');
});

app.post('/api/admin/login', (req, res) => {
  res.json({ message: 'Login endpoint working' });
});

app.listen(PORT, () => {
  console.log(`Test server running on http://localhost:${PORT}`);
});