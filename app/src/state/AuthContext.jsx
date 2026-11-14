import { createContext, useContext, useState, useMemo } from 'react'
import { PERMISSIONS, ROLES } from '../data/mock.js'

const AuthContext = createContext(null)

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    try {
      const raw = sessionStorage.getItem('orion-demo-user')
      return raw ? JSON.parse(raw) : null
    } catch {
      return null
    }
  })

  const login = (orgName, role) => {
    const u = { orgName, role, loggedInAt: new Date().toISOString() }
    setUser(u)
    try { sessionStorage.setItem('orion-demo-user', JSON.stringify(u)) } catch { /* ignore */ }
  }
  const logout = () => {
    setUser(null)
    try { sessionStorage.removeItem('orion-demo-user') } catch { /* ignore */ }
  }

  const value = useMemo(() => ({
    user,
    login,
    logout,
    role: user?.role || null,
    roleMeta: user ? ROLES[user.role] : null,
    can: (perm) => (user ? !!PERMISSIONS[user.role]?.[perm] : false),
  }), [user])

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used inside AuthProvider')
  return ctx
}
