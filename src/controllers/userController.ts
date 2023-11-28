import ApiError from '../errors/ApiError'
import {Request,Response,NextFunction} from 'express'
import User from '../models/user'
import crypto from 'crypto'
import bcrypt from 'bcrypt'
import { validateUser } from '../middlewares/userValdiation'

type Filter = {

  role? : 'visitor'| 'admin'
}

function generateActivationToken() {
  return crypto.randomBytes(32).toString('hex')
}


export const getAllUsers = async (req:Request, res:Response) => {
  const filter : Filter = {}

    const page = Number(req.query.page)||1
    const perPage = Number(req.query.perPage) || 3
    const role = req.query.role
    console.log(page, perPage)
   


    if(role && typeof role==='string') {
      if(role == 'admin') {
        filter.role = role
      }
      if(role == 'visitor') {
        filter.role = role
      }
    }

    const totalUsers = await User.countDocuments(filter)
    const totalPages = Math.ceil(totalUsers/perPage)

    const users = await User.find(filter)
    .skip((page-1)*perPage)
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

  // Register user a varivaction

  export const register =  async(req:Request, res:Response,next :NextFunction) => {
    const {first_name, last_name, email, password } = req.validatedUser
  
    const userExists = await User.findOne({ email })
    if (userExists) {
      return next(ApiError.badRequest('Email already registered'))
    }
    if (!first_name) {
      next(ApiError.badRequest('First name is required'));
      return;
  }
  
  if (!last_name) {
      next(ApiError.badRequest('Last name is required'));
      return;
  }
  
  if (!email) {
      next(ApiError.badRequest('Email is required'));
      return;
  }
  
  if (!password) {
      next(ApiError.badRequest('Password is required'));
      return;
  }
  
    const activationToken = generateActivationToken()
    // TODO: talk about hasing and Salt
    const hashedPassword = await bcrypt.hash(password, 10)
  
   
    const newUser = new User({first_name, last_name, email, password: hashedPassword,
      activationToken,role : "visitor"});
    
    await newUser.save()
  
    //TODO: send an email to the user for activation. the email should include the activationToken
  
    res.json({
      msg: 'User registered.',
      user: newUser,
    })
  }

  export const getOneUser = async (req:Request, res:Response) => {
    const userId = req.params.userId
   const user = await User.findById(userId)
   .populate('order')


  res.status(200).json(user)
  } 

   export const DeleteOneUser = async (req:Request, res:Response) => {
    const { userId } = req.params

    const deleteUser =await User.deleteOne({
      _id: userId,
    })
    if(deleteUser['deletedCount'] === 1){
      res.json({
        msg: 'User delete it Successfully done',
      })
    }else{
      res.json({
        msg: 'User not found',
      })
    }
}

export const updateUser = async (req:Request, res:Response) => {
  const new_first_name = req.body.new_first_name
  const new_last_name = req.body.new_last_name
  const new_email = req.body.new_email
  const new_password = req.body.new_password 
  const new_avatar = req.body.new_avatar
  const userId = req.params.userId
  
  const hashedPassword = await bcrypt.hash(new_password, 10)

  const newUser= await User.findByIdAndUpdate(
    userId,
    {
       first_name: new_first_name, last_name: new_last_name ,
       email: new_email, password: hashedPassword , avatar: new_avatar
      },
    {
      new: true,
    }
  )
  if(!newUser) {
    res.json({
      msg: 'User not found',
      
    })
    return
  }

  res.json({
    User: newUser,
  })
}

export const addOneUser = async (req:Request, res:Response,next :NextFunction) => {

    const { first_name, last_name, email, password, role } = req.body;

    if ( !first_name || !last_name || !email || !password || !role) {
      next(ApiError.badRequest('All user details are required'));
      return;
    }
  
    const newUser = new User({first_name, last_name, email, password,role});
    await newUser.save();
      
      
  
    res.json({
      msg: 'done',
      users: newUser,
    })
}

  
   
  
