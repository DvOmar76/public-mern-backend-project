
import { NextFunction, Request, Response } from 'express'
import zod, { string, z, ZodError } from 'zod'
import ApiError from '../errors/ApiError'


export const validateProduct = (req: Request, res: Response, next: NextFunction) => {
    const getSchema = z.object({
        name: (zod.string().nonempty('name is required')).min(5).max(50),
        description: zod.string().min(5).optional()
    })

    try {
        getSchema.parse(req.body)
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