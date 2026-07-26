import { PrismaClient } from '@prisma/client';

// Tek bir Prisma istemcisi — dev'de hot-reload sirasinda coklu baglanti acilmasin diye global'e asilir.
declare global {
  // eslint-disable-next-line no-var
  var __prisma: PrismaClient | undefined;
}

export const prisma = global.__prisma ?? new PrismaClient();
if (process.env.NODE_ENV !== 'production') global.__prisma = prisma;
