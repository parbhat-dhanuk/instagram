import express, { urlencoded } from "express"
import cors from "cors"
import cookieParser from "cookie-parser"
import dotenv from "dotenv"
import connectDB from "./utils/db.js"
dotenv.config()
const app=express()

const PORT=process.env.PORT

//middlewares

app.use(express.json())
app.use(cookieParser())
app.use(urlencoded({extended:true}))

const corsOptions={
    origin:"http://localhost:5173",
    credentials:true
}

app.use(cors(corsOptions))




app.listen(PORT,()=>{
   console.log(`Server listen at port ${PORT}`)
   connectDB()
})