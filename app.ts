import express from 'express';
import dotenv from 'dotenv';
import cors from 'cors';
import cookieParser from 'cookie-parser';

import { credentials } from './utils/credentials';
import { corsOptions } from './utils/corsOptions';
import { AuthController } from './controllers/AuthController';

const app = express();
dotenv.config({ path: '.env' });

app.use(express.json());
app.use(credentials);
app.use(cors(corsOptions));
app.use(cookieParser());

app.use('/', new AuthController().router);

const port = 3000;
app.listen(port, () => {
  return console.log(`Server running on PORT ${port}`);
});
