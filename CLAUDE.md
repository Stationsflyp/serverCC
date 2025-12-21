# OxcyShop - Auth Corp - Instrucciones

## Iniciar el Sistema

### 1. Terminal 1: Iniciar el Servidor FastAPI (Puerto 8000)
```powershell
Set-Location 'c:\Users\delea\Desktop\OxcyShop - Auth Corp'
python server.py
```

### 2. Terminal 2: Iniciar el Servidor Next.js (Puerto 3000)
```powershell
Set-Location 'c:\Users\delea\Desktop\OxcyShop - Auth Corp\OxcyShop_AuthWebsite'
npm run dev
```

## URLs
- **Web Dashboard**: http://localhost:3000
- **API Backend**: http://localhost:8000/api

## Credenciales de Login
El login se realiza automáticamente al hacer clic en "Entrar con Discord":
- El sistema genera un `app_name` automático del formato: `OxcyShop_XXXXXXX`
- El servidor devuelve: `owner_id` y `secret`
- Las credenciales se guardan en localStorage

## Características Implementadas
✅ Kill Session con force_logout
✅ HWID Reset con aprobación de admin
✅ Ban/Unban de IPs y HWIDs
✅ Gestión de usuarios
✅ Control de versión del cliente

## Problemas Solucionados
✅ Fixed: LoginForm ahora genera credenciales reales desde el servidor
✅ Fixed: .env.local configurado con API_URL
✅ Fixed: ClientProtection movido a page.tsx
✅ Fixed: Hydration warnings con suppressHydrationWarning
✅ Fixed: Notificaciones propias de la web (sin usar browser toast)
✅ Fixed: autocomplete="off" en inputs de password
✅ Fixed: Todos los tabs usan process.env.NEXT_PUBLIC_API_URL en lugar de hardcoded localhost
