import { Router } from "express";
import { loginUser, logoutUser, registeruser , RefreshAccessToken } from "../controllers/user.controllers.js";
import { upload } from "../middlewares/multer.middleware.js";
import { verifyJWT } from "../middlewares/auth.middlewares.js";


const router = Router();

router.route("/register").post(
    upload.fields([
        { name: "avatar", maxCount: 1 },
        { name: "coverImage", maxCount: 1 }
    ]),
    registeruser)


router.route("/login").post(loginUser)    


//secured route
router.route("/logout").post(verifyJWT , logoutUser)
router.route("/refresh-token").post(RefreshAccessToken)


export default router;