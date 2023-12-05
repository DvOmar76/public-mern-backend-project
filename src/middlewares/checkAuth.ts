import jwt from 'jsonwebtoken'
import { NextFunction, Request, Response } from 'express'
import ApiError from '../errors/ApiError'
import { DecodedUser, Role } from '../util/types'

export function checkAuth(expectedRole: Role) {
  return (req: Request, res: Response, next: NextFunction) => {
    const token = req.headers.authorization?.split(' ')[1]

    if (token) {
      try {
        const decodedUser = jwt.verify(token, process.env.JWT_ACCESS_TOKEN_SECRET as string) as DecodedUser

        if (decodedUser.role !== expectedRole) {
          next(ApiError.forbidden('NOT ALLOWED'))
          return
        }

        req.decodedUser = decodedUser
        next()
      } catch (error) {
        next(ApiError.forbidden('invalid token'))
      }
      return
    }
    next(ApiError.forbidden('Token is required'))
  }
}