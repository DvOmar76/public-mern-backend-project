import { NextFunction, Request, Response } from 'express'
import Category from '../models/category'
import ApiError from '../errors/ApiError'
import {
  servicesCreateCategory,
  servicesDeleteCategory,
  servicesGetCategories,
  servicesGetCategory, servicesUpdateCategory
} from "../services/categories";
export const getCategories= async (req:Request, res:Response)=>{
  const categories= await servicesGetCategories()
  res.status(200).json({
    msg:"categories is returned",
    categories:categories
  })
}
export const getCategory= async (req:Request, res:Response ,next:NextFunction)=>{
  const {categoryId}=req.params
  const category= await servicesGetCategory(categoryId);
  if (category!=null) {
    res.status(200).json({
      msg: "category is returned",
      category: category
    })
  }else {
    next(ApiError.badRequest('not found categoryId in db '))
    return
  }
}
export const createCategory= async  (req:Request, res:Response)=>{
// const categories=[
//   {
//     "name": "Electronics"
//   },
//   {
//     "name": "Computers"
//   },
//   {
//     "name": "Mobile Phones"
//   },
//   {
//     "name": "Gaming"
//   },
//   {
//     "name": "Photography"
//   },
//   {
//     "name": "Health & Fitness"
//   },
//   {
//     "name": "Home Entertainment"
//   },
//   {
//     "name": "Home Appliances"
//   },
//   {
//     "name": "Audio"
//   },
//   {
//     "name": "Storage"
//   }
// ]
//  categories.forEach(async (category)=>{
//   const newCategory=  await servicesCreateCategory(category.name)
//
// })
// //   await Category.collection(categories)
//   res.status(201).json({
//     msg: "created categories",
//     category: servicesGetCategories()
//   })
  const {name}=req.body
  const category=  await servicesCreateCategory(name)
  res.status(201).json({
    msg: "created category",
    category: category
  })
}
export const deleteCategory= async (req:Request, res:Response,next:NextFunction) => {
  const  { categoryId } = req.params
  // isDelete['deletedCount']  if  1 => order is deleted
  const isDelete= await servicesDeleteCategory(categoryId)
  // console.log(isDelete)
  if (isDelete['deletedCount'] === 1){
    res.status(204).json({
      msg: 'category is deleted'
    })
  }else {
    res.status(404).json('error')
    next(ApiError.badRequest('not found categoryId in db '))
    return
  }
}

export const updateCategory= async (req:Request, res:Response,next:NextFunction) => {
  const {categoryId}=req.params
  const {name}=req.body
  const findCategory=await servicesGetCategory(categoryId)
  if (findCategory){
    // check if name is unique
    const isUnique=await Category.findOne({name:name}).exec()
    // console.log(isUnique)
    if (!isUnique){
      const updateCategory=await servicesUpdateCategory(categoryId,name)
      if (updateCategory) {
        res.status(200).json({
          msg: "category is updated",
          category: updateCategory
        })
      }else {
        next(ApiError.badRequest("some thing wrong in update "))
      }
    }else {
      next(ApiError.badRequest("another category has same name"))
      return
    }
  }else {
    next(ApiError.badRequest("not found categoryId in db"))
    return
  }

}
