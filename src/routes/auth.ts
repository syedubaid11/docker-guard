import { Router, Request, Response } from 'express';
import { prisma } from '../lib/prisma';

type LoginBody = {
  email?: string;
  password?: string;
};

type SignupBody = {
  name?: string;
  email?: string;
  password?: string;
};

const authRouter = Router();

const userSelect = {
  id: true,
  name: true,
  email: true,
  date_created: true,
} as const;

authRouter.post('/login', async (req: Request, res: Response) => {
  const { email, password } = req.body as LoginBody;

  if (!email || !password) {
    return res.status(400).json({ message: 'email and password are required' });
  }

  try {
    const user = await prisma.users.findFirst({
      where: {
        email,
        password,
      },
      select: userSelect,
    });

    if (!user) {
      return res.status(401).json({ message: 'invalid email or password' });
    }

    return res.status(200).json({
      message: 'login successful',
      user,
    });
  } catch {
    return res.status(500).json({ message: 'failed to login' });
  }
});

authRouter.post('/signup', async (req: Request, res: Response) => {
  const { name, email, password } = req.body as SignupBody;

  if (!name || !email || !password) {
    return res.status(400).json({ message: 'name, email and password are required' });
  }

  try {
    const existingUser = await prisma.users.findFirst({
      where: {
        email,
      },
    });

    if (existingUser) {
      return res.status(409).json({ message: 'email is already registered' });
    }

    const user = await prisma.users.create({
      data: {
        name,
        email,
        password,
        date_created: new Date().toISOString(),
      },
      select: userSelect,
    });

    return res.status(201).json({
      message: 'signup successful',
      user,
    });
  } catch {
    return res.status(500).json({ message: 'failed to create account' });
  }
});

export default authRouter;
