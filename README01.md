# Express.js Backend for Tables Booking System

## 🚀 Quick Start

### 1. Install Dependencies
```bash
cd backend
npm install
```

### 2. Setup Environment Variables
```bash
# Copy env.example to .env
cp env.example .env

# Edit .env and add your Supabase credentials
SUPABASE_URL=https://xxxxx.supabase.co
SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
PORT=5000
```

### 3. Run Server
```bash
# Development mode (with auto-reload)
npm run dev

# Production mode
npm start
```

Server will run on `http://localhost:5000`

---

## 📚 API Endpoints

### Health Check
```
GET /api/health
```

### Authentication
```
POST /api/auth/register
POST /api/auth/login
```

### Concerts
```
GET    /api/concerts
GET    /api/concerts/:id
POST   /api/concerts
PUT    /api/concerts/:id
DELETE /api/concerts/:id
```

### Bookings
```
GET    /api/bookings/concert/:concertId
GET    /api/bookings/phone/:phone
POST   /api/bookings
PUT    /api/bookings/:id
DELETE /api/bookings/:id
```

### Layouts
```
GET    /api/layouts
GET    /api/layouts/:id
POST   /api/layouts
PUT    /api/layouts/:id
DELETE /api/layouts/:id
```

### Settings
```
GET /api/settings
PUT /api/settings/:id
```

---

## 🔧 Frontend Integration

Update your frontend to use the Express backend:

### 1. Update Environment Variables
```env
# frontend/.env.local
NEXT_PUBLIC_API_URL=http://localhost:5000/api
```

### 2. Update API Calls
```typescript
// Before (Next.js API Routes)
const response = await fetch('/api/concerts');

// After (Express Backend)
const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/concerts`);
```

---

## 📁 Project Structure

```
backend/
├── server.js          # Main Express server
├── package.json       # Dependencies
├── env.example        # Environment variables template
└── README.md          # This file
```

---

## 🛠️ Features

- ✅ RESTful API
- ✅ CORS enabled
- ✅ Supabase integration
- ✅ Auto snake_case ↔ camelCase conversion
- ✅ Error handling
- ✅ Development mode with nodemon

---

## 🔒 Security Notes

**Current Implementation:**
- ⚠️ Passwords are stored in plain text
- ⚠️ No JWT authentication
- ⚠️ No rate limiting

**For Production:**
1. Hash passwords with bcrypt
2. Implement JWT tokens
3. Add rate limiting
4. Add input validation
5. Add HTTPS
6. Add API key authentication

---

## 📝 Example Requests

### Register User
```bash
curl -X POST http://localhost:5000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123",
    "name": "John Doe",
    "phone": "0812345678"
  }'
```

### Get All Concerts
```bash
curl http://localhost:5000/api/concerts
```

### Create Booking
```bash
curl -X POST http://localhost:5000/api/bookings \
  -H "Content-Type: application/json" \
  -d '{
    "concertId": 1,
    "tableId": "A1",
    "customerName": "John Doe",
    "customerPhone": "0812345678",
    "status": "confirmed"
  }'
```

---

## 🐛 Troubleshooting

### Port already in use
```bash
# Windows
netstat -ano | findstr :5000
taskkill /PID <PID> /F

# Mac/Linux
lsof -ti:5000 | xargs kill -9
```

### CORS errors
- Make sure CORS is enabled in server.js
- Check that frontend is using correct API URL

### Supabase connection errors
- Verify SUPABASE_URL and SUPABASE_ANON_KEY in .env
- Check Supabase project status
- Verify RLS policies allow access

---

## 📦 Dependencies

- **express**: Web framework
- **cors**: Enable CORS
- **dotenv**: Environment variables
- **@supabase/supabase-js**: Supabase client
- **bcryptjs**: Password hashing (not implemented yet)
- **jsonwebtoken**: JWT tokens (not implemented yet)
- **nodemon**: Auto-reload in development

---

## 🚀 Deployment

### Heroku
```bash
# Install Heroku CLI
heroku create your-app-name
git push heroku main
heroku config:set SUPABASE_URL=your_url
heroku config:set SUPABASE_ANON_KEY=your_key
```

### Railway
```bash
# Install Railway CLI
railway init
railway up
```

### Vercel (Serverless)
```bash
# Install Vercel CLI
vercel
```

---

## 📞 Support

For issues or questions, check:
- Server logs in terminal
- Supabase dashboard logs
- Network tab in browser DevTools
