import { Router, Request, Response } from 'express';
import bcrypt from 'bcryptjs';
import { prisma } from '../lib/prisma';
import { signToken } from '../middleware/auth';
import type { LoginBody, SignupBody } from '../types';

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
    const user = await prisma.users.findFirst({ where: { email } });

    if (!user || !user.password) {
      return res.status(401).json({ message: 'invalid email or password' });
    }

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) {
      return res.status(401).json({ message: 'invalid email or password' });
    }

    const token = signToken({ id: user.id, email: user.email ?? '' });

    return res.status(200).json({
      message: 'login successful',
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        date_created: user.date_created,
      },
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
    const existingUser = await prisma.users.findFirst({ where: { email } });
    if (existingUser) {
      return res.status(409).json({ message: 'email is already registered' });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const user = await prisma.users.create({
      data: {
        name,
        email,
        password: passwordHash,
        date_created: new Date().toISOString(),
      },
      select: userSelect,
    });

    const token = signToken({ id: user.id, email: user.email ?? '' });

    return res.status(201).json({
      message: 'signup successful',
      token,
      user,
    });
  } catch {
    return res.status(500).json({ message: 'failed to create account' });
  }
});

export default authRouter;
