import Admin from '../schemas/admin.schema.js';
import { errorHandler } from '../helpers/errorHandle.js';
import { adminValidator } from '../helpers/validation.js'
import { hash, compare } from 'bcrypt';
import { sendMail } from '../utils/mailer.js';
import { generateOTP } from '../utils/otp-generate.js';
import NodeCache from 'node-cache';
import { generateTokens } from '../utils/token.js';
import jwt from 'jsonwebtoken';
import { config } from 'dotenv';
config();

const my_cache = new NodeCache();

class AdminController {

    async addAdmin(req, res) {
        try {
            const check_data = adminValidator.validate(req.body, { abortEarly: false });
            if (check_data.error) {
                return res.status(406).send({
                    error: check_data.error.details
                });
            }
            const { email, username, password, role } = check_data.value;
            const exist_email = await Admin.findOne({ email });
            if (exist_email) {
                return res.status(409).send({
                    error: "Email address already exist"
                });
            }
            const exist_username = await Admin.findOne({ username });
            if (exist_username) {
                return res.status(409).send({
                    error: "Username already exist"
                });
            }
            const hashed_password = await hash(password, 7);
            const new_admin = await Admin.create({
                email, username, hashed_password, role
            });
            return res.status(201).send({
                message: "Admin added successfully",
                data: new_admin
            });
        } catch (error) {
            errorHandler(error, res);
        }
    }

    async signin(req, res) {
        try {
            const { email, password } = req.body;
            const admin = await Admin.findOne({ email });
            if (!admin) {
                return res.status(400).send({
                    error: "Email or password incorrect"
                });
            }
            const check_password = await compare(password, admin.hashed_password);
            if (!check_password) {
                return res.status(400).send({
                    error: "Email or password incorrect"
                });
            }
            const OTP = generateOTP();
            const mail_options = {
                from: process.env.MAIL_USER,
                to: email,
                subject: "Sent verification code to your email",
                html: `<h1>${OTP}</h1>`
            };
            sendMail(mail_options);
            my_cache.set(email, OTP, 120);
            return res.status(200).send({
                message: "Sent verification code to your email",
                data: OTP
            });
        } catch (error) {
            errorHandler(error, res);
        }
    }

    async confirmOTP(req, res) {
        try {
            const { email, code } = req.body;
            const check = my_cache.get(email);
            if (!check) {
                return res.status(400).send({
                    error: "Email incorrect or expired"
                });
            }
            if (check != code) {
                return res.status(400).send({
                    error: "Verification code invalid"
                });
            }
            const admin = await Admin.findOne({ email });
            const payload = { id: admin._id, role: admin.role };
            const tokens = await generateTokens(payload);
            res.cookie('refresh_token', tokens.refresh_token, {
                httpOnly: true,
                maxAge: 30 * 24 * 60 * 60 * 1000,
            });
            return res.status(200).send({
                message: "Admin signed in successfully",
                token: tokens.access_token
            });
        } catch (error) {
            errorHandler(error, res);
        }
    }

    async accessToken(req, res) {
        try {
            const refresh_token = req.cookies.refresh_token;
            if (!refresh_token) {
                return res.status(401).send({
                    error: "Unauthorizated"
                });
            }
            const check = jwt.verify(refresh_token, process.env.REFRESH_TOKEN_KEY);
            if (!check) {
                return res.status(400).send({
                    error: "Forbidden"
                });
            }
            const payload = { id: check.id, role: check.role };
            const access_token = jwt.sign(payload, process.env.ACCESS_TOKEN_KEY, {
                expiresIn: process.env.ACCESS_TOKEN_TIME
            });
            return res.status(200).send({
                message: "Access token success",
                token: access_token
            });
        } catch (error) {
            errorHandler(error, res);
        }
    }

    async signout(req, res) {
        try {
            const cookie = req.headers.cookie;
            const refresh_token = cookie.split('=')[1];
            if (!refresh_token) {
                return res.status(401).send({
                    message: 'Unathorizated'
                });
            }
            jwt.verify(refresh_token, process.env.REFRESH_TOKEN_KEY, (error, user) => {
                if (error) {
                    return res.status(401).send({
                        error
                    });
                }
            });
            res.clearCookie('refresh_token');
            return res.status(200).send({
                message: 'Admin signed out successfully'
            });
        } catch (error) {
            errorHandler(error, res);
        }
    }
}

export default new AdminController;