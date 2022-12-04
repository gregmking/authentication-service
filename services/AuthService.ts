import { AuthRepository } from '../repositories/AuthRepository';
import { HttpCodes } from '../models/HttpCodes';
import crypto from 'crypto';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';

export class AuthService {
  saltRounds: number;

  constructor(saltRounds = 10) {
    this.saltRounds = saltRounds;
  }

  public async registerUser(u_email: string, u_password: string) {
    if (!u_email || !u_password) {
      const error = new Error('Missing user email or password');
      error['code'] = HttpCodes.UNAUTHORIZED;
      throw error;
    }

    // Check if user already exists
    const repository = new AuthRepository();
    const existingUser = await repository.getUser(u_email);

    if (existingUser.u_id) {
      const error = new Error('User with provided email already exists');
      error['code'] = HttpCodes.UNAUTHORIZED;
      throw error;
    }

    // Generate a UUID
    const u_id = crypto.randomUUID();

    // Hash the provided password
    const u_password_hashed = await bcrypt.hash(u_password, this.saltRounds);
    const response = await repository.registerUser(
      u_id,
      u_email,
      u_password_hashed
    );

    return response;
  }

  public async authenticateUser(u_email: string, u_password: string) {
    if (!u_email || !u_password) {
      const error = new Error('Missing user email or password');
      error['code'] = HttpCodes.UNAUTHORIZED;
      throw error;
    }

    // Retreive user information from DB
    const repository = new AuthRepository();
    const response = await repository.getUser(u_email);

    if (!response.u_id) {
      const error = new Error('User with the specified email does not exist');
      error['code'] = HttpCodes.UNAUTHORIZED;
      throw error;
    }

    // Compare plain text password to hashed password retrieved from DB
    const comparedPassword = await bcrypt.compare(
      u_password,
      response.u_password
    );

    // If password does not match, throw error; else, issue JWTs and return
    if (!comparedPassword) {
      const error = new Error('Invalid password');
      error['code'] = HttpCodes.UNAUTHORIZED;
      throw error;
    }

    const u_access_token = jwt.sign(
      {
        u_id: response.u_id,
        u_email: response.u_email,
      },
      process.env.ACCESS_TOKEN_SECRET,
      { expiresIn: process.env.ACCESS_TOKEN_EXPIRATION }
    );
    const u_refresh_token = jwt.sign(
      {
        u_id: response.u_id,
        u_email: response.u_email,
      },
      process.env.REFRESH_TOKEN_SECRET,
      { expiresIn: process.env.REFRESH_TOKEN_EXPIRATION }
    );

    // Save refreshToken in database
    const insertedToken = await repository.insertRefreshToken(
      response.u_id,
      u_refresh_token
    );

    return { insertedToken, u_access_token };
  }

  public async authenticateRefreshToken(u_refresh_token: string) {
    if (!u_refresh_token) {
      const error = new Error('Refresh token not provided');
      error['code'] = HttpCodes.UNAUTHORIZED;
      throw error;
    }

    // Check for user with provided refresh token in DB
    const repository = new AuthRepository();
    const response = await repository.getUserByToken(u_refresh_token);

    if (!response.u_id) {
      const error = new Error('Invalid refresh token');
      error['code'] = HttpCodes.UNAUTHORIZED;
      throw error;
    }

    let u_access_token: string;
    // Evaluate refresh token
    jwt.verify(
      u_refresh_token,
      process.env.REFRESH_TOKEN_SECRET,
      (err, decoded) => {
        if (err || response.u_id !== decoded.u_id) {
          const error = new Error('Invalid refresh token');
          error['code'] = HttpCodes.UNAUTHORIZED;
          throw error;
        }
        u_access_token = jwt.sign(
          { u_id: decoded.u_id, u_email: decoded.u_email },
          process.env.ACCESS_TOKEN_SECRET,
          { expiresIn: process.env.ACCESS_TOKEN_EXPIRATION }
        );
      }
    );

    return { response, u_access_token };
  }

  public async logoutUser(u_refresh_token: string) {
    if (!u_refresh_token) {
      const error = new Error('Refresh token not provided');
      error['code'] = HttpCodes.UNAUTHORIZED;
      throw error;
    }

    // Delete refresh token for matching user
    const repository = new AuthRepository();
    const response = await repository.deleteToken(u_refresh_token);

    if (!response.u_id) {
      return {
        u_id: '',
      };
    }

    return { response };
  }
}
