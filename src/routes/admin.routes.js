import { Router } from "express";
import AdminController from '../controllers/admin.controller.js';

const adminRouter = Router();

adminRouter.post('/add', AdminController.addAdmin);
adminRouter.post('/signin', AdminController.signin);
adminRouter.post('/confirm-otp', AdminController.confirmOTP);
adminRouter.post('/token', AdminController.accessToken);
adminRouter.post('/signout', AdminController.signout);

export default adminRouter;
