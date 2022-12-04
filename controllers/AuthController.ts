import * as express from 'express';
import { HttpCodes } from '../models/HttpCodes';
import { AuthService } from '../services/AuthService';

export class AuthController {
  public router = express.Router();

  constructor() {
    this.initializeRoutes();
  }

  private initializeRoutes() {
    this.router.post('/register', this.registerUser);
    this.router.post('/authenticate', this.authenticateUser);
    this.router.get('/refresh', this.authenticateRefreshToken);
    this.router.get('/logout', this.logoutUser);
  }

  async registerUser(
    request: express.Request,
    response: express.Response,
    next: express.NextFunction
  ) {
    try {
      const service = new AuthService();
      const result = await service.registerUser(
        request.body.u_email,
        request.body.u_password
      );
      return response.status(HttpCodes.CREATED).json({
        status: 'Success',
        result,
      });
    } catch (error) {
      return response.status(error.code || HttpCodes.SERVER_ERROR).json({
        status: 'Error',
        message: error.message,
        result: {},
      });
    }
  }

  async authenticateUser(
    request: express.Request,
    response: express.Response,
    next: express.NextFunction
  ) {
    try {
      const service = new AuthService();
      const result = await service.authenticateUser(
        request.body.u_email,
        request.body.u_password
      );
      response.cookie('u_refresh_token', result.insertedToken.u_refresh_token, {
        httpOnly: true,
        sameSite: 'none',
        secure: true,
        maxAge: 24 * 60 * 60 * 1000,
      });
      return response.status(HttpCodes.OK).json({
        status: 'Success',
        result: {
          u_id: result.insertedToken.u_id,
          u_access_token: result.u_access_token,
        },
      });
    } catch (error) {
      return response.status(error.code || HttpCodes.SERVER_ERROR).json({
        status: 'Error',
        message: error.message,
        result: {},
      });
    }
  }

  async authenticateRefreshToken(
    request: express.Request,
    response: express.Response,
    next: express.NextFunction
  ) {
    try {
      if (!request.cookies?.u_refresh_token) {
        return response.status(HttpCodes.UNAUTHORIZED).json({
          status: 'Unauthorized',
          result: {},
        });
      }
      const service = new AuthService();
      const result = await service.authenticateRefreshToken(
        request.cookies.u_refresh_token
      );
      return response.status(HttpCodes.OK).json({
        status: 'Success',
        result: {
          u_id: result.response.u_id,
          u_access_token: result.u_access_token,
        },
      });
    } catch (error) {
      return response.status(error.code || HttpCodes.SERVER_ERROR).json({
        status: 'Error',
        message: error.message,
        result: {},
      });
    }
  }

  async logoutUser(
    request: express.Request,
    response: express.Response,
    next: express.NextFunction
  ) {
    try {
      if (!request.cookies?.u_refresh_token) {
        return response.status(HttpCodes.NO_CONTENT).json({
          status: 'Success',
          result: {},
        });
      }
      const service = new AuthService();
      const result = await service.logoutUser(request.cookies.u_refresh_token);

      response.clearCookie('u_refresh_token', {
        httpOnly: true,
        sameSite: 'none',
        secure: true,
      });

      return response.status(HttpCodes.OK).json({
        status: 'Success',
        result: {
          u_id: result.response.u_id,
        },
      });
    } catch (error) {
      return response.status(error.code || HttpCodes.SERVER_ERROR).json({
        status: 'Error',
        message: error.message,
        result: {},
      });
    }
  }
}
