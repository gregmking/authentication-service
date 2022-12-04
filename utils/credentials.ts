import * as express from 'express';
import { allowedOrigins } from './allowedOrigins';

export const credentials = (
  request: express.Request,
  response: express.Response,
  next: express.NextFunction
) => {
  const origin = request.headers.origin;
  if (allowedOrigins.includes(origin)) {
    response.header('Access-Control-Allow-Credentials', 'true');
  }
  next();
};
