/**
 * Discord OAuth Authentication Handler
 * Vercel Serverless Function for Discord OAuth2 flow
 * Version: 2.0.0
 */

import { createClient } from '@supabase/supabase-js';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

// Environment variables validation
const requiredEnvVars = [
    'DISCORD_CLIENT_ID',
    'DISCORD_CLIENT_SECRET', 
    'SUPABASE_URL',
    'SUPABASE_SERVICE_KEY',
    'JWT_SECRET',
    'TARGET_GUILD_ID'
];

function validateEnvironment() {
    const missing = requiredEnvVars.filter(envVar => !process.env[envVar]);
    if (missing.length > 0) {
        throw new Error(`Missing required environment variables: ${missing.join(', ')}`);
    }
}

// Initialize Supabase client
let supabase = null;
function getSupabaseClient() {
    if (!supabase) {
        supabase = createClient(
            process.env.SUPABASE_URL,
            process.env.SUPABASE_SERVICE_KEY,
            {
                auth: {
                    autoRefreshToken: false,
                    persistSession: false
                }
            }
        );
    }
    return supabase;
}

// Discord API helpers
class DiscordAPI {
    static async exchangeCodeForToken(code, redirectUri) {
        const tokenUrl = 'https://discord.com/api/oauth2/token';
        
        const params = new URLSearchParams({
            client_id: process.env.DISCORD_CLIENT_ID,
            client_secret: process.env.DISCORD_CLIENT_SECRET,
            grant_type: 'authorization_code',
            code: code,
            redirect_uri: redirectUri
        });
        
        const response = await fetch(tokenUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
                'User-Agent': 'DiscordAuth/2.0.0'
            },
            body: params.toString()
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Discord token exchange failed: ${response.status} ${errorText}`);
        }
        
        return await response.json();
    }
    
    static async getUserInfo(accessToken) {
        const response = await fetch('https://discord.com/api/v10/users/@me', {
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'User-Agent': 'DiscordAuth/2.0.0'
            }
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Discord user info failed: ${response.status} ${errorText}`);
        }
        
        return await response.json();
    }
    
    static async getUserGuilds(accessToken) {
        const response = await fetch('https://discord.com/api/v10/users/@me/guilds', {
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'User-Agent': 'DiscordAuth/2.0.0'
            }
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error(`Discord guilds fetch failed: ${response.status} ${errorText}`);
        }
        
        return await response.json();
    }
    
    static formatAvatarUrl(userId, avatarHash) {
        if (!avatarHash) {
            const defaultAvatarIndex = parseInt(userId) % 5;
            return `https://cdn.discordapp.com/embed/avatars/${defaultAvatarIndex}.png`;
        }
        
        const extension = avatarHash.startsWith('a_') ? 'gif' : 'png';
        return `https://cdn.discordapp.com/avatars/${userId}/${avatarHash}.${extension}?size=512`;
    }
}

// Database helpers
class DatabaseManager {
    constructor() {
        this.supabase = getSupabaseClient();
    }
    
    async upsertUser(userData) {
        const { data, error } = await this.supabase
            .from('users')
            .upsert({
                discord_id: userData.discord_id,
                username: userData.username,
                discriminator: userData.discriminator,
                display_name: userData.display_name,
                avatar_hash: userData.avatar_hash,
                avatar_url: userData.avatar_url,
                email: userData.email,
                verified: userData.verified,
                locale: userData.locale,
                mfa_enabled: userData.mfa_enabled,
                premium_type: userData.premium_type,
                public_flags: userData.public_flags,
                
                // Auth data
                access_token: userData.access_token,
                refresh_token: userData.refresh_token,
                token_expires_at: userData.token_expires_at,
                
                // Guild data
                guilds: userData.guilds,
                is_target_member: userData.is_target_member,
                target_member_since: userData.target_member_since,
                owned_guilds: userData.owned_guilds,
                
                // Metadata
                last_authenticated: new Date().toISOString(),
                ip_address: userData.ip_address,
                user_agent: userData.user_agent,
                
                // Update existing record or set first_authenticated for new users
                first_authenticated: userData.first_authenticated || new Date().toISOString()
            }, {
                onConflict: 'discord_id',
                ignoreDuplicates: false
            })
            .select()
            .single();
        
        if (error) {
            console.error('Database upsert error:', error);
            throw new Error(`Database operation failed: ${error.message}`);
        }
        
        return data;
    }
    
    async getUser(discordId) {
        const { data, error } = await this.supabase
            .from('users')
            .select('*')
            .eq('discord_id', discordId)
            .single();
        
        if (error && error.code !== 'PGRST116') { // PGRST116 = no rows returned
            console.error('Database select error:', error);
            throw new Error(`Database query failed: ${error.message}`);
        }
        
        return data;
    }
    
    async logAuditEvent(eventData) {
        try {
            await this.supabase
                .from('audit_logs')
                .insert({
                    action: eventData.action,
                    user_id: eventData.user_id,
                    target_user_id: eventData.target_user_id,
                    ip_address: eventData.ip_address,
                    user_agent: eventData.user_agent,
                    details: eventData.details,
                    success: eventData.success,
                    error_message: eventData.error_message,
                    timestamp: new Date().toISOString()
                });
        } catch (error) {
            console.error('Audit log error:', error);
            // Don't throw error for audit logging failures
        }
    }
}

// Rate limiting
const rateLimitMap = new Map();

function checkRateLimit(identifier, maxRequests = 5, windowMs = 15 * 60 * 1000) {
    const now = Date.now();
    const windowStart = now - windowMs;
    
    if (!rateLimitMap.has(identifier)) {
        rateLimitMap.set(identifier, []);
    }
    
    const requests = rateLimitMap.get(identifier);
    
    // Remove old requests outside the window
    const validRequests = requests.filter(timestamp => timestamp > windowStart);
    rateLimitMap.set(identifier, validRequests);
    
    // Check if rate limit exceeded
    if (validRequests.length >= maxRequests) {
        return false;
    }
    
    // Add current request
    validRequests.push(now);
    return true;
}

// Security helpers
function validateState(receivedState, storedStateData) {
    if (!receivedState || !storedStateData) {
        return false;
    }
    
    try {
        const stateData = JSON.parse(storedStateData);
        
        // Check state match
        if (stateData.state !== receivedState) {
            return false;
        }
        
        // Check timestamp (max 10 minutes old)
        const maxAge = 10 * 60 * 1000; // 10 minutes
        if (Date.now() - stateData.timestamp > maxAge) {
            return false;
        }
        
        return true;
    } catch {
        return false;
    }
}

function getClientIP(req) {
    return req.headers['x-forwarded-for'] || 
           req.headers['x-real-ip'] || 
           req.connection?.remoteAddress || 
           'unknown';
}

function generateJWT(userData) {
    const payload = {
        sub: userData.discord_id,
        username: userData.username,
        display_name: userData.display_name,
        avatar_url: userData.avatar_url,
        is_target_member: userData.is_target_member,
        role_assigned: userData.role_assigned,
        is_admin: userData.is_admin || false,
        iat: Math.floor(Date.now() / 1000),
        exp: Math.floor(Date.now() / 1000) + (7 * 24 * 60 * 60) // 7 days
    };
    
    return jwt.sign(payload, process.env.JWT_SECRET, {
        algorithm: 'HS256',
        issuer: 'discord-auth-system',
        audience: 'dashboard'
    });
}

// Main handler
export default async function handler(req, res) {
    // Set CORS headers
    res.setHeader('Access-Control-Allow-Credentials', true);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
    res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version');
    
    if (req.method === 'OPTIONS') {
        res.status(200).end();
        return;
    }
    
    if (req.method !== 'POST') {
        return res.status(405).json({
            success: false,
            error: 'method_not_allowed',
            message: 'Only POST method is allowed'
        });
    }
    
    const startTime = Date.now();
    const clientIP = getClientIP(req);
    const userAgent = req.headers['user-agent'] || 'unknown';
    
    let dbManager = null;
    let userData = null;
    
    try {
        // Validate environment
        validateEnvironment();
        
        // Initialize database manager
        dbManager = new DatabaseManager();
        
        // Rate limiting
        if (!checkRateLimit(clientIP, 10, 15 * 60 * 1000)) {
            await dbManager.logAuditEvent({
                action: 'oauth_rate_limited',
                ip_address: clientIP,
                user_agent: userAgent,
                details: { reason: 'too_many_requests' },
                success: false,
                error_message: 'Rate limit exceeded'
            });
            
            return res.status(429).json({
                success: false,
                error: 'rate_limited',
                message: 'Too many requests. Please try again later.',
                retry_after: 900 // 15 minutes
            });
        }
        
        // Validate request body
        const { code, state, redirect_uri } = req.body;
        
        if (!code) {
            return res.status(400).json({
                success: false,
                error: 'missing_code',
                message: 'Authorization code is required'
            });
        }
        
        if (!redirect_uri) {
            return res.status(400).json({
                success: false,
                error: 'missing_redirect_uri',
                message: 'Redirect URI is required'
            });
        }
        
        console.log(`[OAuth] Processing request from ${clientIP}`);
        
        // Exchange code for token
        console.log('[OAuth] Exchanging code for token...');
        const tokenData = await DiscordAPI.exchangeCodeForToken(code, redirect_uri);
        
        if (!tokenData.access_token) {
            throw new Error('No access token received from Discord');
        }
        
        // Get user information
        console.log('[OAuth] Fetching user information...');
        const discordUser = await DiscordAPI.getUserInfo(tokenData.access_token);
        
        // Get user guilds
        console.log('[OAuth] Fetching user guilds...');
        const userGuilds = await DiscordAPI.getUserGuilds(tokenData.access_token);
        
        // Check target guild membership
        const targetGuildId = process.env.TARGET_GUILD_ID;
        const targetGuild = userGuilds.find(guild => guild.id === targetGuildId);
        const isTargetMember = !!targetGuild;
        
        // Process guild data
        const processedGuilds = userGuilds.map(guild => ({
            id: guild.id,
            name: guild.name,
            icon: guild.icon,
            owner: guild.owner,
            permissions: guild.permissions,
            features: guild.features || []
        }));
        
        const ownedGuilds = processedGuilds.filter(guild => guild.owner);
        
        // Calculate token expiration
        const tokenExpiresAt = new Date(Date.now() + (tokenData.expires_in * 1000)).toISOString();
        
        // Prepare user data for database
        const dbUserData = {
            discord_id: discordUser.id,
            username: discordUser.username,
            discriminator: discordUser.discriminator,
            display_name: discordUser.global_name || discordUser.username,
            avatar_hash: discordUser.avatar,
            avatar_url: DiscordAPI.formatAvatarUrl(discordUser.id, discordUser.avatar),
            email: discordUser.email,
            verified: discordUser.verified,
            locale: discordUser.locale,
            mfa_enabled: discordUser.mfa_enabled,
            premium_type: discordUser.premium_type,
            public_flags: discordUser.public_flags,
            
            // Auth tokens
            access_token: tokenData.access_token,
            refresh_token: tokenData.refresh_token,
            token_expires_at: tokenExpiresAt,
            
            // Guild information
            guilds: processedGuilds,
            is_target_member: isTargetMember,
            target_member_since: isTargetMember ? new Date().toISOString() : null,
            owned_guilds: ownedGuilds,
            
            // Request metadata
            ip_address: clientIP,
            user_agent: userAgent
        };
        
        // Check if user already exists
        const existingUser = await dbManager.getUser(discordUser.id);
        if (existingUser) {
            // Preserve first_authenticated timestamp
            dbUserData.first_authenticated = existingUser.first_authenticated;
            
            // If user was already a target member, preserve that timestamp
            if (existingUser.is_target_member && existingUser.target_member_since) {
                dbUserData.target_member_since = existingUser.target_member_since;
            }
        }
        
        // Save user to database
        console.log('[OAuth] Saving user to database...');
        userData = await dbManager.upsertUser(dbUserData);
        
        // Generate JWT token
        const jwtToken = generateJWT({
            discord_id: userData.discord_id,
            username: userData.username,
            display_name: userData.display_name,
            avatar_url: userData.avatar_url,
            is_target_member: userData.is_target_member,
            role_assigned: userData.role_assigned || false,
            is_admin: userData.is_admin || false
        });
        
        // Log successful authentication
        await dbManager.logAuditEvent({
            action: 'oauth_authentication_success',
            user_id: userData.discord_id,
            ip_address: clientIP,
            user_agent: userAgent,
            details: {
                username: userData.display_name,
                guild_count: processedGuilds.length,
                is_target_member: isTargetMember,
                target_guild_id: targetGuildId,
                owned_guilds_count: ownedGuilds.length,
                processing_time_ms: Date.now() - startTime
            },
            success: true
        });
        
        // Prepare response data
        const responseUser = {
            id: userData.discord_id,
            username: userData.username,
            discriminator: userData.discriminator,
            display_name: userData.display_name,
            avatar_url: userData.avatar_url,
            email: userData.email,
            verified: userData.verified,
            is_target_member: userData.is_target_member,
            role_assigned: userData.role_assigned || false,
            guild_count: processedGuilds.length,
            owned_guilds_count: ownedGuilds.length,
            first_authenticated: userData.first_authenticated,
            last_authenticated: userData.last_authenticated,
            target_member_since: userData.target_member_since,
            guilds: processedGuilds.slice(0, 10) // Limit guilds in response
        };
        
        console.log(`[OAuth] Authentication successful for ${userData.display_name} (${userData.discord_id})`);
        
        // Return success response
        return res.status(200).json({
            success: true,
            message: 'Authentication successful',
            data: {
                token: jwtToken,
                user: responseUser,
                expires_in: 7 * 24 * 60 * 60, // 7 days in seconds
                token_type: 'Bearer'
            }
        });
        
    } catch (error) {
        console.error('[OAuth] Authentication error:', error);
        
        // Log failed authentication
        if (dbManager) {
            await dbManager.logAuditEvent({
                action: 'oauth_authentication_failed',
                user_id: userData?.discord_id || null,
                ip_address: clientIP,
                user_agent: userAgent,
                details: {
                    error_message: error.message,
                    error_type: error.constructor.name,
                    processing_time_ms: Date.now() - startTime
                },
                success: false,
                error_message: error.message
            });
        }
        
        // Determine error response based on error type
        let statusCode = 500;
        let errorCode = 'internal_error';
        let message = 'Authentication failed due to internal error';
        
        if (error.message.includes('Discord token exchange failed')) {
            statusCode = 400;
            errorCode = 'token_exchange_failed';
            message = 'Failed to exchange authorization code. Please try again.';
        } else if (error.message.includes('Discord user info failed')) {
            statusCode = 400;
            errorCode = 'user_info_failed';
            message = 'Failed to retrieve user information from Discord.';
        } else if (error.message.includes('Discord guilds fetch failed')) {
            statusCode = 400;
            errorCode = 'guilds_fetch_failed';
            message = 'Failed to retrieve server information from Discord.';
        } else if (error.message.includes('Database operation failed')) {
            statusCode = 500;
            errorCode = 'database_error';
            message = 'Failed to save authentication data. Please try again.';
        } else if (error.message.includes('Missing required environment variables')) {
            statusCode = 500;
            errorCode = 'configuration_error';
            message = 'Server configuration error. Please contact support.';
        }
        
        return res.status(statusCode).json({
            success: false,
            error: errorCode,
            message: message,
            ...(process.env.NODE_ENV === 'development' && {
                debug: {
                    error_details: error.message,
                    stack_trace: error.stack
                }
            })
        });
    }
}

// Export configuration for Vercel
export const config = {
    api: {
        bodyParser: {
            sizeLimit: '1mb',
        },
    },
    // Enable Edge Runtime for better performance
    runtime: 'nodejs18.x',
    maxDuration: 30, // 30 seconds timeout
};