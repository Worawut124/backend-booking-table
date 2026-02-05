# ========================================
# Backend Setup Instructions
# ========================================

## Step 1: Create .env file

Copy your Supabase credentials from frontend/.env.local to backend/.env

```bash
cd backend
```

Create a new file called `.env` with this content:

```env
SUPABASE_URL=https://xxxxx.supabase.co
SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
PORT=5000
NODE_ENV=development
```

## Step 2: Start the backend server

```bash
npm run dev
```

You should see:
```
🚀 Backend server running on http://localhost:5000
📊 API endpoints available at http://localhost:5000/api
```

## Step 3: Test the API

Open browser and go to:
```
http://localhost:5000/api/health
```

You should see:
```json
{
  "status": "OK",
  "message": "Backend is running"
}
```

## Step 4: Update Frontend (Optional)

If you want to use this Express backend instead of Next.js API routes:

1. Update `frontend/.env.local`:
```env
NEXT_PUBLIC_API_URL=http://localhost:5000/api
```

2. Update all API calls in your code to use the new URL

---

## Quick Commands

```bash
# Install dependencies
npm install

# Run in development mode (auto-reload)
npm run dev

# Run in production mode
npm start
```

---

## Troubleshooting

### Port 5000 already in use
```bash
# Change PORT in .env file
PORT=5001
```

### Cannot find module errors
```bash
npm install
```

### Supabase connection errors
- Check SUPABASE_URL and SUPABASE_ANON_KEY in .env
- Make sure they match your frontend/.env.local
```
