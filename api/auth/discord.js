/**
 * Discord OAuth Authentication Handler
 * Simplified version without Supabase
 */
import jwt from 'jsonwebtoken';

export default async function handler(req, res) {
    // CORS headers
    res.setHeader('Access-Control-Allow-Credentials', true);
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
    res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Content-Type, Authorization');
    
    if (req.method === 'OPTIONS') {
        res.status(200).end();
        return;
    }
    
    if (req.method !== 'POST') {
        return res.status(405).json({
            success: false,
            error: 'method_not_allowed',
            message: 'Only POST method allowed'
        });
    }

    try {
        const { code, redirect_uri } = req.body;
        
        if (!code) {
            return res.status(400).json({
                success: false,
                error: 'missing_code',
                message: 'Authorization code required'
            });
        }

        // 1. Exchange code for Discord token
        const tokenResponse = await fetch('https://discord.com/api/oauth2/token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: new URLSearchParams({
                client_id: process.env.DISCORD_CLIENT_ID,
                client_secret: process.env.DISCORD_CLIENT_SECRET,
                grant_type: 'authorization_code',
                code: code,
                redirect_uri: redirect_uri || 'https://yourdomain.com/auth-callback.html'
            })
        });

        if (!tokenResponse.ok) {
            throw new Error('Discord token exchange failed');
        }

        const tokenData = await tokenResponse.json();

        // 2. Get user info from Discord
        const userResponse = await fetch('https://discord.com/api/users/@me', {
            headers: {
                'Authorization': `Bearer ${tokenData.access_token}`
            }
        });

        if (!userResponse.ok) {
            throw new Error('Failed to get user info');
        }

        const userData = await userResponse.json();

        // 3. Get user guilds
        const guildsResponse = await fetch('https://discord.com/api/users/@me/guilds', {
            headers: {
                'Authorization': `Bearer ${tokenData.access_token}`
            }
        });

        const guildsData = guildsResponse.ok ? await guildsResponse.json() : [];

        // 4. Check target guild membership
        const isTargetMember = guildsData.some(guild => guild.id === process.env.TARGET_GUILD_ID);

        // 5. Create JWT token
        const jwtPayload = {
            sub: userData.id,
            username: userData.username,
            display_name: userData.global_name || userData.username,
            avatar_url: userData.avatar ? 
                `https://cdn.discordapp.com/avatars/${userData.id}/${userData.avatar}.png` : 
                'https://cdn.discordapp.com/embed/avatars/0.png',
            is_target_member: isTargetMember,
            guild_count: guildsData.length,
            iat: Math.floor(Date.now() / 1000),
            exp: Math.floor(Date.now() / 1000) + (7 * 24 * 60 * 60) // 7 days
        };

        const token = jwt.sign(jwtPayload, process.env.JWT_SECRET);

        // 6. Return success
        return res.status(200).json({
            success: true,
            message: 'Authentication successful',
            data: {
                token: token,
                user: {
                    id: userData.id,
                    username: userData.username,
                    display_name: userData.global_name || userData.username,
                    avatar_url: jwtPayload.avatar_url,
                    is_target_member: isTargetMember,
                    guild_count: guildsData.length,
                    verified: userData.verified
                }
            }
        });

    } catch (error) {
        console.error('OAuth error:', error);
        
        return res.status(500).json({
            success: false,
            error: 'authentication_failed',
            message: 'Authentication failed'
        });
    }
}

export const config = {
  runtime: 'nodejs'
};


