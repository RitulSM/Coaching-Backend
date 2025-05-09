require('dotenv').config();
const connectDB = require('./config/db');
const app = require('./app');

const adminRoutes = require('./routes/admin');
const userRoutes = require('./routes/user');

// Health check endpoint
app.get('/', (req, res) => {
  res.status(200).json({ status: 'ok', message: 'Server is running' });
});

app.use('/admin', adminRoutes);
app.use('/user', userRoutes);

connectDB();

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));