import { NextFunction, Request, Response } from 'express'

export function checkUserOwnership(req: Request, res: Response, next: NextFunction) {
  if (req.decodedUser.role === 'admin') {
    req.userId = req.params.userId
  } else {
    req.userId = req.decodedUser.userId
  }
  next()
}
