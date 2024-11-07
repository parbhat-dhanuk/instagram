import User from "../models/userModel.js"
import bcrypt from "bcryptjs"
import jwt from "jsonwebtoken"


export const register=async (req,res)=>{
    try {
        const {username,email,password}=req.body
        if(!username||!email||!password){
            return res.status(401).json({
                message:"please provide email or password or username",
                success:false
            })
        }
        const user=await User.findOne({email})
        if(user){
            return res.status(401).json({
                message:"try different email",
                success:false
            })
        }
        const hashPassword=await bcrypt.hash(password,10)
        await User.create({
            email,
            username,
            password:hashPassword
        })
        return res.status(201).json({
            message:"Account created successfully",
            success:true
        })
    } catch (error) {
        console.log(error)
    }
}

export const login=async (req,res)=>{
    try {
        const {email,password}=req.body
        if(!email||!password){
            return res.status(401).json({
                message:"please provide email or password",
                success:false
            })
        }
        const user=await User.findOne({email})
        if(!user){
            return res.status(401).json({
                message:"Incorrect email or password",
                success:false
            })
        }
        const isPassordMatch=await bcrypt.compare(password,user.password)
        if(!isPassordMatch){
            return res.status(401).json({
                message:"Incorrect email or password",
                success:false
            })
        }

        const token = await jwt.sign({userId:user._id},process.env.SECRET_KEY,{expiredIn:"1d"})

         user={
             _id:user._id,
             username:user.username,
             email:user.email,
             profilePicture: user.profilePicture,
             bio: user.bio,
             followers: user.followers,
             following: user.following,
             posts: user.post
        }

        return res.cookie("token",token,{httpOnly:true,sameSite:"strict",maxAge:1*24*60*60*1000}).json({
            message:`Welcome${user.username}`,
            success:true,
            user
        })
    } catch (error) {
        console.log(error)
    }
}


export const logout=async (_,res)=>{
    try {
        return res.cookie("token","",{maxAge:0}).json({
            message:"logged out successfully",
            success:true
        })
    } catch (error) {
        console.log(error)
    }
}