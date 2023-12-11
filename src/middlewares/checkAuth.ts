import jwt from 'jsonwebtoken'
import { NextFunction, Request, Response } from 'express'
import ApiError from '../errors/ApiError'
import { DecodedUser, Role } from '../util/types'

export function checkAuth(...expectedRole: Role[]) {
  return (req: Request, res: Response, next: NextFunction) => {
       // console.log(expectedRole,req.decodedUser)
      try {
        const decodedUser = req.decodedUser
        const isAllowed = expectedRole.includes(decodedUser.role)
        if (!isAllowed) {
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
    // next(ApiError.forbidden('Token is required'))
  }
