import ApiError from '../errors/ApiError'
import { Request, Response, NextFunction } from 'express'
import User from '../models/user'
import bcrypt from 'bcrypt'
import { generateActivationToken, sendActivationEmail } from '../util/email'
import jwt from 'jsonwebtoken'
import apiError from '../errors/ApiError'

type Filter = {

  role?: 'visitor' | 'admin'
}
export const getAllUsers = async (req: Request, res: Response) => {
  const filter: Filter = {}
  const page = Number(req.query.page) || 1
  const perPage = Number(req.query.perPage) || 3
  const role = req.query.role
  console.log(req.decodedUser)


  if (role && typeof role === 'string') {
    if (role == 'admin') {
      filter.role = role
    }
    if (role == 'visitor') {
      filter.role = role
    }
  }

  const totalUsers = await User.countDocuments(filter)
  const totalPages = Math.ceil(totalUsers / perPage)

  const users = await User.find(filter)
    .skip((page - 1) * perPage)
    .limit(perPage)
    .populate('order')

  res.json({
      page,
      perPage,
      totalUsers,
      totalPages,
      users
    }
  )
}
export const register = async (req: Request, res: Response, next: NextFunction) => {
  const { firstName, lastName, email, password,avatar } = req.validatedUser
  try {
    const userExists = await User.findOne({ email })
    if (userExists) {
      return next(ApiError.badRequest('Email already registered'))
    }
    if (!firstName || !lastName || !email || !password ) {
      next(ApiError.badRequest('all fields required first_name , last_name , email , password'))
      return
    }
    const activationToken = generateActivationToken()
    const hashedPassword = await bcrypt.hash(password, 10)
    const newUser = new User({
      firstName, lastName, email, password: hashedPassword,
      activationToken, role: 'visitor',avatar
    })
    await newUser.save()
    await sendActivationEmail(email, activationToken)
    res.json({
      message: 'User registered. Check your email to activate your account!',
      user: newUser
    })
  } catch (error) {
    console.log('error:', error)
    next(ApiError.badRequest('Something went wrong'))
  }
}

export const login = async (req: Request, res: Response, next: NextFunction) => {
  // step_1: fetch email and password
  const { email, password } = req.validatedLoginUser
  try {
    // step_2: check if email in database or not
    const user = await User.findOne({ email }).exec()
    // console.log(user)
    // if not found user return this message
    if (!user) {
      return res.status(401).json({
        message: 'User is not found '
      })
    }
    //step_3: compare password from user with database (password in db is hashed by bcrypt)
    bcrypt.compare(password, user.password, (err, result) => {
      if (err) {
        return res.status(401).json({
          message: 'Password is not correct '
        })
      }
      if (result) {
        // step_4: create access token
        const accessToken = jwt.sign(
          {
            email: user.email,
            userId: user._id,
            role: user.role
          },
          process.env.JWT_ACCESS_TOKEN_SECRET as string,
          {
            expiresIn: '24h' // you can use minute -> m
          }
        )
        // step_5 : create a cookie and add access token to it
        res.cookie('accessToken', accessToken, {
          maxAge: 5 * 60 * 1000,  // expired after 5 mint
          secure: true,
          sameSite: 'none'
          // httpOnly: true, // create cookie in http that mean you don't found this cookies in browser
          // sameSite: 'none'// read about it i think it's link your site

        })

        return res.status(200).json({
          message: 'Login is successful',
          token: accessToken,
          user: user
        })
      } else {
        return res.status(401).json({
          message: 'Login is not successful'
        })
      }
    })
  } catch (error) {
    console.log('Error in login', error)
    return res.status(500).json({
      message: 'Cannot find user'
    })
  }
}
export const logout = async (req: Request, res: Response, next: NextFunction) => {
  try {
    res.clearCookie('accessToken')
    return res.status(200).json({
      message: 'user is logged out'
    })
  } catch (error) {
    return res.status(500).json({
      message: 'Error in logout'
    })
  }
}


export const activation = async (req: Request, res: Response, next: NextFunction) => {
  const activationToken = req.params.activationToken
  const user = await User.findOne({ activationToken })
  if (!user) {
    next(ApiError.badRequest('Invalid activation token'))
    return
  }
  user.isActive = true
  user.activationToken = undefined
  await user.save()
  res.status(200).json({
    message: 'Account activated successfully'
  })
}

export const getOneUser = async (req: Request, res: Response, next: NextFunction) => {
  const userId = req.userId
  // get user info without password
  //TODO: remove _id
  const user = await User.findById(userId)
    .populate('order').exec()
  if (user) {
    res.status(200).json(user)
  } else {
    next(ApiError.badRequest('wrong user id '))
  }
}

export const DeleteOneUser = async (req: Request, res: Response) => {
  const { userId } = req.params

  const deleteUser = await User.deleteOne({
    _id: userId
  })
  if (deleteUser['deletedCount'] === 1) {
    res.json({
      message: 'User delete it Successfully done'
    })
  } else {
    res.json({
      message: 'User not found'
    })
  }
}

export const updateUser = async (req: Request, res: Response) => {
  const new_first_name = req.body.new_first_name
  const new_last_name = req.body.new_last_name
  const new_email = req.body.new_email
  const new_password = req.body.new_password
  const new_avatar = req.body.new_avatar
  const userId = req.params.userId

  const hashedPassword = await bcrypt.hash(new_password, 10)

  const newUser = await User.findByIdAndUpdate(
    userId,
    {
      first_name: new_first_name, last_name: new_last_name,
      email: new_email, password: hashedPassword, avatar: new_avatar
    },
    {
      new: true
    }
  )
  if (!newUser) {
    res.json({
      message: 'User not found'
    })
    return
  }
  res.json({
    User: newUser
  })
}

export const addOneUser = async (req: Request, res: Response, next: NextFunction) => {
  const { first_name, last_name, email, password, role } = req.body
  if (!first_name || !last_name || !email || !password || !role) {
    next(ApiError.badRequest('All user details are required'))
    return
  }
  const newUser = new User({ first_name, last_name, email, password, role })
  await newUser.save()
  res.json({
    message: 'done',
    users: newUser
  })
}
export const isLoggedIn = (req: Request, res: Response, next: NextFunction) => {
  const accessToken = req.cookies.accessToken
  const secretKey = process.env.JWT_ACCESS_TOKEN_SECRET
  // console.log(accessToken ,!accessToken)

  if (!accessToken) {
    next(apiError.badRequest('you are not logged in'))
    return
  }
  if (!secretKey) {
    next(apiError.badRequest('invalid access token'))
    return
  }
  const decoded = jwt.verify(accessToken, secretKey) as {
    userId: string;
    email: string;
    role: 'visitor' | 'admin';
    iat: number;
    exp: number;
  }
  req.decodedUser = decoded
  next()
}
export const isLoggedOut = (req: Request, res: Response, next: NextFunction) => {
  const accessToken = req.cookies.accessToken
  if (accessToken) {
    next(apiError.badRequest('you are logged in'))
    return
  }
  next()
}

  
   
  
