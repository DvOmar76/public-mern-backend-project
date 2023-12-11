import zod, { ZodError } from 'zod'
import { NextFunction, Request, Response } from 'express'
import ApiError from '../errors/ApiError'

export function validateUser(req: Request, res: Response, next: NextFunction) {
  const schema = zod.object({
    firstName: zod.string(),// Adjust validation as needed
    lastName: zod.string(),
    email: zod.string().email(),
    password: zod.string().min(6),
    avatar: zod.string().optional()
  })
  try {
    const validatedUser = schema.parse(req.body)
    req.validatedUser = validatedUser
    schema.parse(req.body)
    next()
  } catch (error) {
    const err = error
    if (err instanceof ZodError) {
      next(ApiError.badRequestValidation(err.errors))
      return
    }
    next(ApiError.internal('Something went wrong'))
  }
}

export function validateUpdateUser(req: Request, res: Response, next: NextFunction) {
  const schema = zod.object({
    new_firstName: zod.string().optional(), // Adjust validation as needed
    new_lastName: zod.string().optional(),
    new_email: zod.string().email().optional(),
    new_password: zod.string().min(8).max(50).optional(), // Adjust the password constraints
    new_avatar: zod.string().url().optional()
  })

  try {
    schema.parse(req.body)
    next()
  } catch (error) {
    const err = error
    if (err instanceof ZodError) {
      next(ApiError.badRequestValidation(err.errors))
      return
    }
    next(ApiError.internal('Something went wrong'))
  }
}

export function validateLoginUser(req: Request, res: Response, next: NextFunction) {
  const schema = zod.object({
    email: zod.string().email(),
    password: zod.string().min(5).max(50) // Adjust the password constraints

  })
  try {
    const validatedLoginUser = schema.parse(req.body)
    req.validatedLoginUser = validatedLoginUser
    next()
  } catch (error) {
    const err = error
    if (err instanceof ZodError) {
      next(ApiError.badRequestValidation(err.errors))
      return
    }
    next(ApiError.internal('Something went wrong'))
  }
}


export function validateUserID(req: Request, res: Response, next: NextFunction) {
  const schema = zod.object({
    userId: zod.string().length(24)
  })
  try {
    schema.parse(req.params)
    next()
  } catch (error) {
    const err = error
    if (err instanceof ZodError) {
      next(ApiError.badRequestValidation(err.errors))
      return
    }
    next(ApiError.internal('Something went wrong'))
  }
}
