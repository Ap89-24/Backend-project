import { asynchandler } from "../utils/asynchandler.js";
import { ApiError } from "../utils/apierrors.js";
import { User } from "../models/user.models.js";
import { uploadonCloudinary } from "../utils/cloudinary.js";
import { Apiresponse  } from "../utils/apiresponse.js";
import jwt from "jsonwebtoken";


const generateAccessandRefreshTokens =  async(userId) =>{
    try {
        const user = await User.findById(userId);
        const accessToken = user.generateAccessToken();
        const refreshToken = user.generateRefreshToken();


        user.refreshToken = refreshToken;
       await user.save({validateBeforeSave: false});

        return {accessToken, refreshToken};

    } catch (error) {
        throw new ApiError(500,"Something went wrong when generating refresh and access tokens");
    }
}


const registeruser = asynchandler( async(req,res)=> {
  //GET USER DETAIL FROM FRONTEND......
  //VALIDATION - NOT EMPTY AND CORRECT FROMATTING
  //CHECK IF USER ALREADY EXISTS CHECK WITH USERNAME AND EMAIL....
  //CHECK FOR IMAGES AND AVATAR....
  //UPLOAD THEM TO CLOUDINARY CHECK AVATAR....
  //CREATE USER OBJECT - CREATE ENTRY IN DB....
  //REMOVE PASSWORD AND REFRESH TOKEN FIELD FROM RESPONSE.....
  //CHECK FOR USRE CREATION.....
  //AND RETURN RESPONSE.....     




  const {username , password , email , fullname} = req.body
  console.log("username:" , username);
  console.log("password:" , password);
  console.log("email:" , email);
  console.log("fullname:" , fullname);

if (
  [fullname,email.username,password].some((field)=> field?.trim()==="")  
) {
    throw new ApiError(400,"All fields are required..")
}

const existedUser = await User.findOne({
    $or: [{ username },{ email }]
})


if (existedUser) {
    throw new ApiError(409,"username and email are already exist");
}


const avtarlocalpath = req.files?.avatar[0]?.path;
const coverimagelocalpath = req.files?.coverImage[0]?.path;
console.log(req.files);


if (!avtarlocalpath) {
    throw new ApiError(400,"avatar file is required");
}

const avatar = await uploadonCloudinary(avtarlocalpath);
const coverimage = await uploadonCloudinary(coverimagelocalpath);


if (!avatar) {
    throw new ApiError(400,"avatar file is required");
}


const user = await User.create({
    fullname,
    avatar: avatar.url,
    coverImage: coverimage?.url || "",
    username: username.toLowerCase(),
    email,
    password
})

const usercreated = await User.findById(user._id).select("-password -refreshToken");

if (!usercreated) {
    throw new ApiError(500,"something went wrong while registering a user");
}

return res.status(200).json(
    new Apiresponse(200,usercreated,"user registered successfully")
);

})


const loginUser = asynchandler( async(req,res)=>{
      //GET DATA FROM REQ BODY...
      //GET LOGIN THROUGH USERNAME OR EMAIL....
      //CHECK FOR USER EXISTS...
      //CHECK FOR PASSWORD....
      //CREATE ACCESS AND REFRESH JWT TOKEN....
      //SEND COOKIES...


      const {email,username,password} = req.body
      console.log("username:" , username);
      console.log("password:" , password);
      console.log("email:" , email);
      
      if (!email && !username) {
        throw new ApiError(400,"email or username is required");
      }

      const user = await User.findOne({
        $or: [{username} , {email}],
      })

      if(!user){
        throw new ApiError(401,"invalid username or email");
      }

      const isPassCorrect = await user.isPasswordCorrect(password);

      if(!isPassCorrect){
        throw new ApiError(401,"Password is incorrect");
      }


      const {accessToken , refreshToken} = await generateAccessandRefreshTokens(user._id);

      const loggedInuser = await User.findById(user._id).select("-password -refreshToken");

    const options = {
        httpOnly : true,
        secure: true
    }

    return res
    .status(200)
    .cookie("accessToken", accessToken, options)
    .cookie("refreshToken", refreshToken,options)
    .json(
        new Apiresponse(
            200,
            {
                user: loggedInuser,accessToken,refreshToken
            },
            "User logged in successfully"
        )
    )
})

const logoutUser = asynchandler( async(req,res) => {
      await  User.findByIdAndUpdate(req.user._id,{
        $set: {
            refreshToken: undefined
        }
      },
      {
        new: true
      },
    )

    const options = {
        httpOnly : true,
        secure: true
    }

    return res
    .status(200)
    .clearCookie("accessToken",options)
    .clearCookie("refreshToken",options)
    .json(new Apiresponse(200,{},"User looged out successfully"))

})


const RefreshAccessToken = asynchandler(async(req,res)=> {
  
  //GET REFRESH TOKEN FROM COOKIES...
  //VALIDATE THE TOKEN...
  //GET USER ID FROM THE TOKEN...
  //GENERATE NEW ACCESS AND REFRESH TOKEN...
  //SEND COOKIES...

  const incomingRefreshToken = req.cookies.refreshToken || req.body.refreshToken

  if (!incomingRefreshToken) {
    throw new ApiError(401, "unauthorized request");
  }

try {
  
    const decodedToken = jwt.verify(incomingRefreshToken, process.env.REFRESH_TOKEN_SECRET);
  
    const user = await User.findById(decodedToken?._id)
  
    if (!user) {
      throw new ApiError(401, "Invalid refresh token");
    }
  
    if (incomingRefreshToken !== user?.refreshToken) {
      throw new ApiError(401, "Refresh token is expired or used");
    }
  
    const options = {
      httpOnly: true,
      secure: true
    }
  
    const {accessToken , NewrefreshToken} = await generateAccessandRefreshTokens(user._id)
  
    return res
    .status(200)
    .cookie("access token" , accessToken , options)
    .cookie("refresh token", NewrefreshToken, options)
    .json(
        new Apiresponse(
          200,
          {accessToken , refreshToken: NewrefreshToken},
          "User access token refreshed successfully"
        )
    )
  
} catch (error) {
    throw new ApiError(401, error?.message || "Invalid refresh token")
}

})


const changeCurrentPassword = asynchandler(async(req , res) => {
    const {oldPassword , newPassword , confPassword} = req.body
    
    const user = await User.findById(req.user?._id)
    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)

    if (!isPasswordCorrect) {
      throw new ApiError(400 , "Invalid password");
    }

    user.password = newPassword;
    await user.save({validateBeforeSave: false})

    if (!(newPassword === confPassword)) {
      throw new ApiError(400 , "Password doesn't match");
    }

    return res
    .status(200)
    .json(new Apiresponse(200 , {} , "Password changes successfully"))
})

const getCurrentUser = asynchandler(async(req,res)=> {
  return res
  .status(200)
  .json(200, req.user , "Current user fetched successfully")
})

const updateAccountDetails = asynchandler(async(req,res) => {
       const {fullname , email} = req.body;
       if (!fullname || !email) {
        throw new ApiError(400 , "All fields are required");
       }

    const user = User.findByIdAndUpdate(
      req.user?._id,
      {
        $set: {
          fullname,
          email
        }
      },
      {new: true}
    ).select("-password")   

    return res
    .status(200)
    .json(new Apiresponse(200,user,"Account details updated successfully")) 
})

const updateUserAvatar = asynchandler(async(req,res) => {
  const avtarlocalpath = req.file?.path

  if (!avtarlocalpath) {
    throw new ApiError(401, "File not found")
  }

  const avatar = await uploadonCloudinary(avtarlocalpath)
  
  if (!avatar.url)  {
    throw new ApiError(400, "Error while uploading an avatar")
   }

  const user = await User.findByIdAndUpdate(
    req.user?._id,
    {
      $set:{
        avatar: avatar.url
      }
    },
    {new: true}
   ).select("-password")

   return res
   .status(200)
   .json(new Apiresponse(200, user , "Avatar image updated successfully"))
})

const updateUserCoverImage = asynchandler(async(req,res) => {
  const coverImagelocalpath = req.file?.path

  if (!coverImagelocalpath) {
    throw new ApiError(401, "Cover file not found")
  }

  const coverimage = await uploadonCloudinary(coverImagelocalpath)
  
  if (!coverimage.url)  {
    throw new ApiError(400, "Error while uploading an cover file")
   }

  const user = await User.findByIdAndUpdate(
    req.user?._id,
    {
      $set:{
        coverimage : coverimage.url
      }
    },
    {new: true}
   ).select("-password")

   return res
    .status(200)
    .json(new Apiresponse(200, user , "Cover image updated successfully"))
})



export { registeruser,
         loginUser,
         logoutUser,
         RefreshAccessToken,
         changeCurrentPassword,
         getCurrentUser,
         updateAccountDetails,
         updateUserAvatar,
         updateUserCoverImage
       }