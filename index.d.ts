declare namespace Express {
  interface Request {
    validatedUser: {
      firstName: string
      lastName: string
      email: string
      password: string
      avatar?: string | undefined
    }
    decodedUser: {
      userId: string
      email: string
      role: 'visitor' | 'admin'
      iat: number
      exp: number
    }
    validatedLoginUser: {
      email: string
      password: string
    }
    userId: string
   
  }
  
}