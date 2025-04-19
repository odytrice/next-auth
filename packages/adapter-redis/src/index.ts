/**
 * <div style={{display: "flex", justifyContent: "space-between", alignItems: "center", padding: 16}}>
 *  <p>Official <a href="https://redis.io/">Redis</a> adapter for Auth.js / NextAuth.js.</p>
 *  <a href="https://redis.io/">
 *   <img style={{display: "block"}} src="https://redis.io/wp-content/uploads/2024/04/Logotype.svg" width="60"/>
 *  </a>
 * </div>
 *
 * ## Installation
 *
 * ```bash npm2yarn
 * npm install ioredis @auth/upstash-redis-adapter
 * ```
 *
 * @module @auth/redis-adapter
 */
import type { Adapter, AdapterUser, AdapterAccount, AdapterSession, VerificationToken } from "@auth/core/adapters";
import { isDate } from "@auth/core/adapters";
import type { Redis } from "ioredis"; // Assuming you use ioredis

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * Configuration options for the Redis Adapter.
 */
export interface RedisAdapterOptions {
  /** Prefix for all keys stored in Redis. Default: "auth:" */
  keyPrefix?: string;
  /** TTL (in seconds) for user sessions. Default: 30 days */
  sessionTimeoutSeconds?: number;
  /** TTL (in seconds) for verification tokens. Default: 1 day */
  verificationTokenTimeoutSeconds?: number;
}

export function hydrateDates(json: object) {
  return Object.entries(json).reduce((acc, [key, val]) => {
    acc[key] = isDate(val) ? new Date(val as string) : val
    return acc
  }, {} as any)
}

/**
 * Creates an Auth.js Adapter for Redis using ioredis.
 *
 * @param client - An initialized ioredis client instance.
 * @param options - Optional configuration for key prefixes and timeouts.
 * @returns An object implementing the Auth.js Adapter interface.
 */
export function RedisAdapter(client: Redis, options: RedisAdapterOptions = {}): Adapter {
  const {
    keyPrefix = "auth:",
    sessionTimeoutSeconds = 30 * 24 * 60 * 60, // 30 days
    verificationTokenTimeoutSeconds = 24 * 60 * 60, // 1 day
  } = options;

  // --- Key Generation Functions ---
  const Key = {
    User: (id: string) => `${keyPrefix}user:${id}`,
    UserEmail: (email: string) => `${keyPrefix}user:email:${email}`, // Stores user ID
    Account: (provider: string, providerAccountId: string) => `${keyPrefix}account:${provider}:${providerAccountId}`, // Stores Account object + userId
    AccountByUserId: (userId: string) => `${keyPrefix}user:accounts:${userId}`, // Set of account keys (provider:providerAccountId)
    Session: (sessionToken: string) => `${keyPrefix}session:${sessionToken}`, // Stores Session object + userId
    SessionByUserId: (userId: string) => `${keyPrefix}user:sessions:${userId}`, // Set of session tokens
    VerificationToken: (identifier: string, token: string) => `${keyPrefix}verification-token:${identifier}:${token}`, // Stores VerificationToken object
  };

  // --- Helper Functions ---
  const setObject = async (key: string, data: Record<string, any>, expires?: number) => {
    const validData: Record<string, string> = {};
    for (const [prop, value] of Object.entries(data)) {
      if (value !== null && value !== undefined) {
        validData[prop] = value instanceof Date ? value.toISOString() : String(value);
      }
    }
    if (Object.keys(validData).length === 0) return; // Don't store empty objects

    await client.hset(key, validData);
    if (expires) {
      await client.expire(key, expires);
    }
  };

  const getObject = async <T extends Record<string, any>>(key: string): Promise<(T & { [key: string]: any }) | null> => {
    const data = await client.hgetall(key);
    if (!data || Object.keys(data).length === 0) {
      return null;
    }
    // Convert date strings back to Date objects and numbers where appropriate
    const result: Record<string, any> = {};
    for (const [prop, value] of Object.entries(data)) {
      // Basic check for ISO date string format (YYYY-MM-DDTHH:mm:ss.sssZ)
      if (typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z$/.test(value)) {
        result[prop] = new Date(value);
      } else if (!isNaN(Number(value))) {
        // Check if it looks like an email verification expires timestamp
        if (prop === 'expires' && value.length === 13) { // Simple check for ms timestamp
          result[prop] = new Date(parseInt(value, 10));
        } else if (prop !== 'email' && prop !== 'id' && prop !== 'userId' && prop !== 'provider' && prop !== 'providerAccountId' && prop !== 'sessionToken' && prop !== 'token' && prop !== 'identifier') {
          // Avoid converting ID-like fields to numbers
          result[prop] = Number(value);
        } else {
          result[prop] = value;
        }
      }
      else {
        result[prop] = value;
      }
    }
    return result as T;
  };

  // --- Adapter Methods ---

  const createUser = async (user: Omit<AdapterUser, "id">): Promise<AdapterUser> => {
    const id = crypto.randomUUID();
    const newUser = { ...user, id };
    const userKey = Key.User(id);
    const emailKey = Key.UserEmail(user.email);

    // Use MULTI/EXEC for atomicity
    const multi = client.multi();
    multi.set(emailKey, id); // Link email to user ID
    multi.hset(userKey, newUser as any); // Store user object
    await multi.exec();

    return newUser;
  };

  const getUser = async (id: string): Promise<AdapterUser | null> => {
    return getObject<AdapterUser>(Key.User(id));
  };

  const getUserByEmail = async (email: string): Promise<AdapterUser | null> => {
    const userId = await client.get(Key.UserEmail(email));
    if (!userId) return null;
    return getUser(userId);
  };

  const getUserByAccount = async ({ providerAccountId, provider }: Pick<AdapterAccount, "provider" | "providerAccountId">): Promise<AdapterUser | null> => {
    const accountKey = Key.Account(provider, providerAccountId);
    const account = await getObject<AdapterAccount>(accountKey);
    if (!account?.userId) return null;
    return getUser(account.userId);
  };

  const updateUser = async (user: Partial<AdapterUser> & Pick<AdapterUser, "id">): Promise<AdapterUser> => {
    const userKey = Key.User(user.id);
    const currentUser = await getObject<AdapterUser>(userKey);
    if (!currentUser) throw new Error("User not found");

    // Update email mapping if email changes
    if (user.email && user.email !== currentUser.email) {
      const oldEmailKey = Key.UserEmail(currentUser.email);
      const newEmailKey = Key.UserEmail(user.email);
      const multi = client.multi();
      multi.del(oldEmailKey);
      multi.set(newEmailKey, user.id);
      await multi.exec(); // Consider error handling for exec
    }

    const updatedUser = { ...currentUser, ...user };
    await setObject(userKey, updatedUser);
    return updatedUser;
  };

  const deleteUser = async (userId: string): Promise<AdapterUser | null> => {
    const userKey = Key.User(userId);
    const user = await getObject<AdapterUser>(userKey);
    if (!user) return null;

    // Keys for related data
    const emailKey = Key.UserEmail(user.email);
    const accountsSetKey = Key.AccountByUserId(userId);
    const sessionsSetKey = Key.SessionByUserId(userId);

    // Get linked accounts and sessions
    const accountKeysToDelete = await client.smembers(accountsSetKey);
    const sessionTokensToDelete = await client.smembers(sessionsSetKey);

    // Use MULTI/EXEC to delete user and all related data atomically
    const multi = client.multi();
    multi.del(userKey);
    multi.del(emailKey);
    if (accountKeysToDelete.length > 0) {
      multi.del(accountKeysToDelete.map(accKeyStr => Key.Account(...accKeyStr.split(':') as [string, string]))); // Reconstruct full account key
      multi.del(accountsSetKey);
    }
    if (sessionTokensToDelete.length > 0) {
      multi.del(sessionTokensToDelete.map(token => Key.Session(token)));
      multi.del(sessionsSetKey);
    }

    await multi.exec(); // Consider error handling for exec

    // Note: deleteUser is expected to return void or the user object in some adapter versions.
    // Returning the user object before deletion seems common. Check @auth/core types if needed.
    return user;
  };


  const linkAccount = async (account: AdapterAccount): Promise<AdapterAccount | null> => {
    const accountKey = Key.Account(account.provider, account.providerAccountId);
    const accountsSetKey = Key.AccountByUserId(account.userId);
    const accountKeyString = `${account.provider}:${account.providerAccountId}`; // Store simplified key in set

    const multi = client.multi();
    multi.hset(accountKey, account as any); // Store account object
    multi.sadd(accountsSetKey, accountKeyString); // Add account key string to user's set
    await multi.exec();

    return account; // Return the input account as per Adapter spec
  };

  const unlinkAccount = async ({ providerAccountId, provider }: Pick<AdapterAccount, "provider" | "providerAccountId">): Promise<AdapterAccount | undefined> => {
    const accountKey = Key.Account(provider, providerAccountId);
    const account = await getObject<AdapterAccount>(accountKey); // Fetch account to get userId
    if (!account) return undefined; // Or throw? Spec says return void/undefined

    const accountsSetKey = Key.AccountByUserId(account.userId);
    const accountKeyString = `${provider}:${providerAccountId}`;

    const multi = client.multi();
    multi.del(accountKey); // Delete the account hash
    multi.srem(accountsSetKey, accountKeyString); // Remove from user's set
    await multi.exec();

    return account; // Return the deleted account object
  };

  const createSession = async (session: { sessionToken: string; userId: string; expires: Date }): Promise<AdapterSession> => {
    const sessionKey = Key.Session(session.sessionToken);
    const sessionsSetKey = Key.SessionByUserId(session.userId);
    const sessionData = { ...session };

    const multi = client.multi();
    multi.hset(sessionKey, sessionData as any);
    multi.expire(sessionKey, sessionTimeoutSeconds);
    multi.sadd(sessionsSetKey, session.sessionToken); // Add session token to user's set
    await multi.exec();

    return sessionData;
  };

  const getSessionAndUser = async (sessionToken: string): Promise<{ session: AdapterSession; user: AdapterUser } | null> => {
    const sessionKey = Key.Session(sessionToken);
    const session = await getObject<AdapterSession>(sessionKey);

    if (!session || session.expires < new Date()) {
      if (session) {
        // Clean up expired session
        const sessionsSetKey = Key.SessionByUserId(session.userId);
        const multi = client.multi();
        multi.del(sessionKey);
        multi.srem(sessionsSetKey, sessionToken);
        await multi.exec();
      }
      return null;
    }

    const user = await getUser(session.userId);
    if (!user) return null; // User associated with session not found

    return { session, user };
  };

  const updateSession = async (session: Partial<AdapterSession> & Pick<AdapterSession, "sessionToken">): Promise<AdapterSession | null> => {
    const sessionKey = Key.Session(session.sessionToken);
    const currentSession = await getObject<AdapterSession>(sessionKey);
    if (!currentSession) return null;

    const updatedSession = { ...currentSession, ...session };
    await setObject(sessionKey, updatedSession, sessionTimeoutSeconds); // Reset expiry on update

    return updatedSession;
  };

  const deleteSession = async (sessionToken: string): Promise<AdapterSession | null> => {
    const sessionKey = Key.Session(sessionToken);
    const session = await getObject<AdapterSession>(sessionKey);
    if (!session) return null;

    const sessionsSetKey = Key.SessionByUserId(session.userId);
    const multi = client.multi();
    multi.del(sessionKey);
    multi.srem(sessionsSetKey, sessionToken); // Remove from user's set
    await multi.exec();

    return session; // Return deleted session
  };

  const createVerificationToken = async (verificationToken: VerificationToken): Promise<VerificationToken | null> => {
    const tokenKey = Key.VerificationToken(verificationToken.identifier, verificationToken.token);
    await setObject(tokenKey, verificationToken, verificationTokenTimeoutSeconds);
    return verificationToken;
  };

  const useVerificationToken = async ({ identifier, token }: { identifier: string; token: string }): Promise<VerificationToken | null> => {
    const tokenKey = Key.VerificationToken(identifier, token);
    const verificationToken = await getObject<VerificationToken>(tokenKey);

    if (!verificationToken || verificationToken.expires < new Date()) {
      return null; // Token not found or expired
    }

    // Atomically delete the token
    await client.del(tokenKey);
    return verificationToken;
  };

  // Return the adapter object conforming to the Adapter interface
  return {
    createUser,
    getUser,
    getUserByEmail,
    getUserByAccount,
    updateUser,
    deleteUser,
    linkAccount,
    unlinkAccount,
    createSession,
    getSessionAndUser,
    updateSession,
    deleteSession,
    createVerificationToken,
    useVerificationToken,
  };
}
