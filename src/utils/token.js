import jwt from 'jsonwebtoken';
import { config } from 'dotenv';
config();

export const generateTokens = async (payload) => {
    try {
        const [refresh_token, access_token] = await Promise.all([
            jwt.sign(payload, process.env.REFRESH_TOKEN_KEY, {
                expiresIn: process.env.REFRESH_TOKEN_TIME,
            }),
            jwt.sign(payload, process.env.ACCESS_TOKEN_KEY, {
                expiresIn: process.env.ACCESS_TOKEN_TIME,
            }),
        ]);
        return {
            refresh_token, access_token
        }
    } catch (error) {
        console.log(`Error on generate tokens: ${error}`);
    }
}