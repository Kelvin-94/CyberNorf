import { toNextJsHandler } from 'better-auth/next-js';
import { auth } from '@/lib/auth';

/**
 * Better Auth owns every credential, session, and second-factor endpoint under
 * /api/auth. Rate limits and cookie settings live in `src/lib/auth.ts`.
 */
export const { GET, POST } = toNextJsHandler(auth);
