# Coaching Backend

## Deployment to Vercel

### Prerequisites
- A Vercel account
- MongoDB Atlas account (or any MongoDB provider)
- Node.js installed locally for testing

### Environment Variables
Set up the following environment variables in your Vercel project settings:

- `PORT`: Default port for the server (Vercel will override this)
- `MONGO_URI`: Your MongoDB connection string
- `JWT_SECRET`: Secret key for JWT token generation
- `FRONTEND_URL`: URL of your frontend application
- `RAZORPAY_KEY_ID`: Razorpay Key ID (if using Razorpay)
- `RAZORPAY_KEY_SECRET`: Razorpay Key Secret (if using Razorpay)

### Deployment Steps

1. Fork or clone this repository
2. Link it to your Vercel account:
   ```
   vercel login
   vercel link
   ```
3. Deploy to Vercel:
   ```
   vercel --prod
   ```

### Local Development
1. Clone the repository
2. Create a `.env` file with the variables listed above
3. Install dependencies:
   ```
   npm install
   ```
4. Run the development server:
   ```
   npm run dev
   ```

## API Endpoints

- `/admin` - Admin routes
- `/user` - User routes 