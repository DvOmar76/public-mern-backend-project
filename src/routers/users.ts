import express from 'express'

import ApiError from '../errors/ApiError'
import User from '../models/user'
import {
  DeleteOneUser,
  activation,
  addOneUser,
  getAllUsers,
  getOneUser,
  login,
  register,
  updateUser,
  logout,
  isLoggedIn, isLoggedOut
} from '../controllers/userController'
import { validateLoginUser, validateUpdateUser, validateUser, validateUserID } from '../middlewares/userValdiation'
import { checkAuth } from '../middlewares/checkAuth'
import { checkUserOwnership } from '../middlewares/checkUserOwnership'
const router = express.Router()

//List all Users : work
router.get('/',isLoggedIn,checkAuth("admin"), getAllUsers)

//List one user : work
router.get('/:userId',isLoggedIn,validateUserID, checkUserOwnership,getOneUser)


//Delete User : work
router.delete('/:userId',isLoggedIn,validateUserID, DeleteOneUser)


//Update user : Work
router.put('/:userId',isLoggedIn,validateUserID,validateUpdateUser, updateUser)

//Add User : work
router.post('/',isLoggedIn , addOneUser)



// validateUser  zod validate
router.post('/register',isLoggedOut,validateUser, register)
//validateLoginUser zod validate
router.post('/login',isLoggedOut,validateLoginUser, login)
router.post('/logout',isLoggedIn, logout)

router.get('/activateUser/:activationToken',activation)





// router.get('/:userId/page/:page', (req, res) => {
//   res.json({
//     msg: 'done',
//     user: req.user,
//   })
// })

// router.get('/', async (_, res) => {
//   const users = await User.find().populate('order')
//   res.json({
//     users,
//   })
// })

export default router


