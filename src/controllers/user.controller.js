import asyncHandler from '../utils/asyncHandler.js'
import ApiError from '../utils/ApiError.js'
import { User } from '../models/user.models.js'
import { uploadOnCloudinary } from '../utils/cloudinary.js'
import { ApiResponse } from '../utils/ApiResponse.js'

export const registerUser = asyncHandler(async (req, res) => {
    //get user details
    //validation
    //check if user exists
    //check for images, check for avatar
    //upload them to cloudinary, avatar
    //create user object - create entry in db
    //remove password and refresh token
    //check for user creation from response
    //return res


    const { username, email, fullname, password } = req.body
    console.log("email:", email)

    if (fullname === "") {
        throw new ApiError(400, "fullname is required")
    }
    if (username === "") {
        throw new ApiError(400, "username is required")
    }
    if (email === "") {
        throw new ApiError(400, "email is required")
    }
    if (password === "") {
        throw new ApiError(400, "password is required")
    }



    const existingUsername = await User.findOne({ username })
    const existingEmail = await User.findOne({ email })

    if (existingUsername) {
        throw new ApiError(409, "Username already exists")
    }
    if (existingEmail) {
        throw new ApiError(409, "Email already exists")
    }



    const avatarLocalPath = req.files?.avatar[0]?.path;
    //const coverImageLocalPath = req.files?.coverImage[0]?.path;

    let coverImageLocalPath;
    if (req.files && Array.isArray(req.files.coverImage) && req.files.coverImage.length > 0) {
        coverImageLocalPath = req.files.coverImage[0]?.path

    }

    if (!avatarLocalPath) {
        throw new ApiError(400, "Avatar file is required")
    }



    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if (!avatar) {
        throw new ApiError(400, "Avatar file is required")

    }


    const user = await User.create({
        fullname,
        avatar: avatar.url,
        coverImage: coverImage?.url || "",
        email,
        password,
        username: username.toLowerCase()
    })

    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )
    if (!createdUser) {
        throw new ApiError(500, "Something went wrong while creating user")
    }


    return res.status(201).json(
        new ApiResponse(200, createdUser, "User registered successfully")
    )
}) 