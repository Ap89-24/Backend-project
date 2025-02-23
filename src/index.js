import dotenv from "dotenv";
import connectDB from "./db/index.js";
import { app } from "./app.js";


dotenv.config({
    path: './.env'
})

connectDB()

.then(() =>{
    app.listen(process.env.PORT || 8000, () => {
        console.log(`server is running on port: ${process.env.PORT}`);
    })
    app.on("error", (err) => {
        console.log("error", err);
        throw err;
    })
})
.catch((error) =>{
    console.log("mongodb connection failed", error);
})











/*
import express from "express";
const app = express();
;( async () => {
     try {
       await mongoose.connect(`${process.env.MONGODB_URL}/${DB_NAME}`);
       app.on("error", (error)=>{
           console.log("error" , error);
           throw error;
       })

       app.listen(process.env.PORT, () =>{
        console.log(`app listening on port ${process.env.PORT}`);
       })

     } catch (error) {
        console.error("error : " , error)
        throw error;
     }
})()
*/