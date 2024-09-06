import nodemailer from 'nodemailer';
import { config } from 'dotenv';
config();

export const sendMail = (mail_options) => {
    try {
        const transporter = nodemailer.createTransport({
            host: process.env.MAIL_HOST,
            port: process.env.MAIL_PORT,
            secure: false,
            auth: {
                user: process.env.MAIL_USER,
                pass: process.env.MAIL_PASS,
            }
        });
        transporter.sendMail(mail_options, function (error, info) {
            if (error) {
                console.log(error);
            } else {
                console.log(info.response)
            }
        });
    } catch (error) {
        console.log(`Error on sending mail: ${error}`);
    }
}