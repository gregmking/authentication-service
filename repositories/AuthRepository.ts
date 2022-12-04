import db from '../db';
import { User } from '../models/User';

export interface IAuthRepository {
  registerUser(
    u_id: string,
    u_email: string,
    u_password_hashed: string
  ): Promise<User>;
  getUser(u_email: string): Promise<User>;
  getUserByToken(u_refresh_token: string): Promise<User>;
  insertRefreshToken(id: string, u_refresh_token: string): Promise<User>;
  deleteToken(u_refresh_token: string): Promise<User>;
}

export class AuthRepository implements IAuthRepository {
  public async registerUser(
    u_id: string,
    u_email: string,
    u_password_hashed: string
  ): Promise<User> {
    const response = await db.query(
      'INSERT INTO users VALUES ($1, $2, $3) RETURNING id;',
      [u_id, u_email, u_password_hashed]
    );

    const registeredUser = new User();
    registeredUser.map(response.rows[0]);

    return registeredUser;
  }

  public async getUser(u_email: string): Promise<User> {
    const response = await db.query(
      'SELECT id, u_password FROM users WHERE u_email = $1;',
      [u_email]
    );

    const retrievedUser = new User();
    retrievedUser.map(response.rows[0]);

    return retrievedUser;
  }

  public async getUserByToken(u_refresh_token: string): Promise<User> {
    const response = await db.query(
      'SELECT id FROM users WHERE u_refresh_token = $1;',
      [u_refresh_token]
    );

    const retrievedUser = new User();
    retrievedUser.map(response.rows[0]);

    return retrievedUser;
  }

  public async insertRefreshToken(
    id: string,
    u_refresh_token: string
  ): Promise<User> {
    const response = await db.query(
      'UPDATE users SET u_refresh_token = $1 WHERE id = $2 RETURNING id, u_refresh_token;',
      [u_refresh_token, id]
    );

    const insertedToken = new User();
    insertedToken.map(response.rows[0]);

    return insertedToken;
  }

  public async deleteToken(u_refresh_token: string): Promise<User> {
    const response = await db.query(
      'UPDATE users SET u_refresh_token = null WHERE u_refresh_token = $1 RETURNING id;',
      [u_refresh_token]
    );

    const deletedToken = new User();
    deletedToken.map(response.rows[0]);

    return deletedToken;
  }
}
