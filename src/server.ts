import express from 'express'
import mongoose from 'mongoose'
import { config } from 'dotenv'
import morgan from 'morgan'
import usersRouter from './routers/users'
import productsRouter from './routers/products'
import categoriesRouter from './routers/category'
import ordersRouter from './routers/orders'
import apiErrorHandler from './middlewares/errorHandler'
import myLogger from './middlewares/logger'
config()
const app = express()
const PORT = 5050
const URL = process.env.ATLAS_URL as string

app.use(morgan('dev'))
app.use(myLogger)
app.use(express.urlencoded({ extended: true }))
app.use(express.json())

app.get("/",(req, res)=>{
    res.json({
        msg:"test"
    })
})

app.use('/api/users', usersRouter)
app.use('/api/orders', ordersRouter)
app.use('/api/products', productsRouter)
app.use('/api/categories', categoriesRouter)

app.use(apiErrorHandler)

mongoose
  .connect(URL)
  .then(() => {
    console.log('Database connected')
  })
  .catch((err) => {
    console.log('MongoDB connection error, ', err)
  })

app.listen(PORT, () => {
  console.log('Server running http://localhost:' + PORT)
})


export default app;