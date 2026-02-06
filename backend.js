const express = require('express');
const AWS = require('aws-sdk');
const Razorpay = require('razorpay');
const crypto = require('crypto');
const multer = require('multer');
const QRCode = require('qrcode');
const session = require('express-session');
const path = require('path');
require('dotenv').config();

const app = express();

// Increased limits for base64 or large form data handling
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// 1. PROVIDER CONFIGURATIONS

// Razorpay Setup
const razorpay = new Razorpay({
    key_id: process.env.RAZORPAY_KEY_ID || 'rzp_test_SBek7WH7u0rVRL',
    key_secret: process.env.RAZORPAY_KEY_SECRET || 'WNuH9N2qNk066Th4xaeqTPlt'
});

// PRIMARY ACCOUNT (DynamoDB & S3)
const primaryConfig = {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    region: process.env.AWS_REGION || 'ap-south-1'
};

const dynamo = new AWS.DynamoDB.DocumentClient(primaryConfig);
const s3 = new AWS.S3(primaryConfig);

// SECONDARY ACCOUNT (SES ONLY)
const ses = new AWS.SES({
    region: 'ap-south-1',
    credentials: {
        accessKeyId: 'AKIAS2VS4CZ2Q4RQV4WX',
        secretAccessKey: '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'
    }
});

// Multer Configuration with 10MB Limit
const upload = multer({ 
    storage: multer.memoryStorage(),
    limits: { fileSize: 10 * 1024 * 1024 } // 10MB limit
});

// SESSION HANDLING
app.use(session({
    name: 'lbrce_sid',
    secret: process.env.JWT_SECRET || 'lbrce-events-2026-secure-key',
    resave: true, 
    saveUninitialized: true,
    cookie: { 
        secure: false, // Set to true if using HTTPS
        httpOnly: true,
        maxAge: 1000 * 60 * 60 * 24 
    } 
}));

// Static File Serving
app.use(express.static('public')); 
app.use('/admin', express.static(path.join(__dirname, 'admin'))); 

// 2. AUTH MIDDLEWARE
const isAdmin = (req, res, next) => {
    if (req.session && req.session.isAdmin) return next();
    res.status(403).json({ error: 'Forbidden: Please log in again.' });
};

// 3. ADMIN AUTHENTICATION
app.post('/api/admin/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await dynamo.get({ TableName: 'LBRCE_Admins', Key: { username } }).promise();
        const user = result.Item;
        if (user && user.password === password) {
            req.session.isAdmin = true;
            req.session.save(() => res.json({ success: true }));
        } else {
            res.status(401).json({ error: 'Invalid credentials' });
        }
    } catch (err) { res.status(500).json({ error: 'Auth service failure' }); }
});

app.get('/api/admin/check-session', (req, res) => {
    res.json({ loggedIn: !!(req.session && req.session.isAdmin) });
});

// 4. EVENT MANAGEMENT (Admin & Public)
app.get('/api/events', async (req, res) => {
    try {
        const data = await dynamo.scan({ TableName: 'LBRCE_Events' }).promise();
        res.json(data.Items);
    } catch (err) { res.status(500).json({ error: 'Fetch failed' }); }
});

app.post('/api/admin/events', isAdmin, upload.single('logo'), async (req, res) => {
    let logoUrl = 'https://res.cloudinary.com/djdwpjm7x/image/upload/v1769924817/admin-block_kgxvrc.jpg';
    
    if (req.file) {
        const params = {
            Bucket: process.env.S3_BUCKET || 'proctorix',
            Key: `event-logos/${Date.now()}-${req.file.originalname.replace(/\s+/g, '_')}`,
            Body: req.file.buffer,
            ContentType: req.file.mimetype
        };
        try {
            const uploadResult = await s3.upload(params).promise();
            logoUrl = uploadResult.Location;
        } catch (err) { 
            return res.status(500).json({ error: `S3 upload failed: ${err.message}` }); 
        }
    }

    const event = {
        eventId: `EVT-${Date.now()}`,
        name: req.body.name,
        description: req.body.description,
        type: req.body.type,
        price: parseFloat(req.body.price || 0),
        teamSize: parseInt(req.body.teamSize || 1),
        sections: JSON.parse(req.body.sections || '[]'),
        logo: logoUrl,
        timestamp: new Date().toISOString()
    };

    try {
        await dynamo.put({ TableName: 'LBRCE_Events', Item: event }).promise();
        res.json({ success: true, event });
    } catch (err) { res.status(500).json({ error: 'Failed to save event' }); }
});

app.put('/api/admin/events/:id', isAdmin, upload.single('logo'), async (req, res) => {
    const { id } = req.params;
    let logoUrl = req.body.existingLogo;

    if (req.file) {
        const params = {
            Bucket: process.env.S3_BUCKET || 'proctorix',
            Key: `event-logos/${Date.now()}-${req.file.originalname.replace(/\s+/g, '_')}`,
            Body: req.file.buffer,
            ContentType: req.file.mimetype
        };
        const uploadResult = await s3.upload(params).promise();
        logoUrl = uploadResult.Location;
    }

    const updated = {
        ...req.body,
        eventId: id,
        price: parseFloat(req.body.price),
        teamSize: parseInt(req.body.teamSize),
        sections: JSON.parse(req.body.sections || '[]'),
        logo: logoUrl,
        timestamp: new Date().toISOString()
    };
    delete updated.existingLogo;

    try {
        await dynamo.put({ TableName: 'LBRCE_Events', Item: updated }).promise();
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: 'Update failed' }); }
});

app.delete('/api/admin/events/:id', isAdmin, async (req, res) => {
    try {
        await dynamo.delete({ TableName: 'LBRCE_Events', Key: { eventId: req.params.id } }).promise();
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: 'Delete failed' }); }
});

// 5. PHOTO UPLOAD ENDPOINT
app.post('/api/upload-photo', (req, res, next) => {
    // Wrap the upload middleware to catch errors
    upload.single('photo')(req, res, (err) => {
        if (err) {
            // Check for Multer-specific errors
            if (err.code === 'LIMIT_FILE_SIZE') {
                return res.status(413).json({ error: 'File size exceeds the 10MB limit.' });
            }
            // Other Multer errors
            return res.status(400).json({ error: `Upload error: ${err.message}` });
        }
        // If no error, proceed to the main handler
        next();
    });
}, async (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'No photo provided' });

    const params = {
        Bucket: process.env.S3_BUCKET || 'proctorix',
        Key: `student-photos/${Date.now()}-${req.file.originalname.replace(/\s+/g, '_')}`,
        Body: req.file.buffer,
        ContentType: req.file.mimetype
    };

    try {
        const uploadResult = await s3.upload(params).promise();
        res.json({ url: uploadResult.Location });
    } catch (err) {
        console.error("S3 Upload Error:", err);
        res.status(500).json({ error: 'Failed to upload photo to S3' });
    }
});

// 6. REGISTRATION & ATTENDANCE VERIFICATION
app.get('/api/registration-details/:id', async (req, res) => {
    try {
        const result = await dynamo.get({
            TableName: 'LBRCE_Registrations',
            Key: { registrationId: req.params.id }
        }).promise();
        if (!result.Item) return res.status(404).json({ error: 'Registration not found' });
        res.json(result.Item);
    } catch (err) { res.status(500).json({ error: 'Database error' }); }
});

/**
 * QR SCAN ENDPOINT: 
 * Marks attendance if scanned by Admin.
 * Otherwise, just shows the details.
 */
app.get('/api/verify-attendance/:id', async (req, res) => {
    const registrationId = req.params.id;
    const { roll } = req.query; // Capture unique participant identifier from QR scan

    try {
        const result = await dynamo.get({
            TableName: 'LBRCE_Registrations',
            Key: { registrationId }
        }).promise();

        if (!result.Item) return res.status(404).json({ error: 'Invalid Ticket' });

        const registration = result.Item;
        
        // Default to lead data
        let participant = {
            name: registration.leadName,
            roll: registration.leadRoll,
            photo: registration.photoUrl,
            role: 'Lead'
        };

        // If a specific roll was scanned and it's not the lead, find that team member
        if (roll && roll !== registration.leadRoll && registration.members) {
            const member = registration.members.find(m => m.roll === roll);
            if (member) {
                participant = {
                    name: member.name,
                    roll: member.roll,
                    photo: member.photoUrl,
                    role: 'Member'
                };
            }
        }

        let message = "Details Retrieved Successfully";
        let status = "Viewed";

        // Mark attendance if the current session is an Admin
        if (req.session && req.session.isAdmin) {
            await dynamo.update({
                TableName: 'LBRCE_Registrations',
                Key: { registrationId },
                UpdateExpression: "set attendance = :a",
                ExpressionAttributeValues: { ":a": true }
            }).promise();
            message = `Attendance Marked for ${participant.name}!`;
            status = "Verified";
        }

        // Return the specific participant's data so the admin scanner shows the right name
        res.json({
            success: true,
            message,
            status,
            data: {
                ...registration,
                leadName: participant.name, // Overwriting leadName for the Admin UI to display the scanned person
                leadRoll: participant.roll,
                photoUrl: participant.photo,
                participantRole: participant.role
            }
        });
    } catch (err) {
        res.status(500).json({ error: 'Verification failed' });
    }
});

app.post('/api/register/create-order', async (req, res) => {
    const amount = parseFloat(req.body.amount);
    if (!amount || amount < 1) return res.status(400).json({ error: 'Amount too low' });
    
    try {
        const order = await razorpay.orders.create({
            amount: Math.round(amount * 100),
            currency: "INR",
            receipt: `rcpt_${Date.now()}`
        });
        res.json(order);
    } catch (err) {
        res.status(500).json({ error: 'Gateway order failed' });
    }
});

app.post('/api/register/verify', async (req, res) => {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, registrationData } = req.body;
    
    const hmac = crypto.createHmac('sha256', process.env.RAZORPAY_KEY_SECRET || 'O97dBbH6AK1zlvM4C96jdzeV');
    hmac.update(razorpay_order_id + "|" + razorpay_payment_id);
    
    if (hmac.digest('hex') !== razorpay_signature) {
        return res.status(400).json({ error: 'Signature mismatch' });
    }

    const regId = `REG-${Date.now()}`;
    try {
        const qrImage = await QRCode.toDataURL(`https://events-lbrce.in/verify-attendance/${regId}`);
        
        const registrationEntry = {
            registrationId: regId,
            paymentId: razorpay_payment_id,
            ...registrationData,
            timestamp: new Date().toISOString()
        };

        await dynamo.put({ TableName: 'LBRCE_Registrations', Item: registrationEntry }).promise();
        
        // --- SEPARATE EMAIL LOGIC ---

        // A. Send Receipt only to Team Lead
        await sendReceiptEmail(registrationEntry);

        // B. Send Individual ID Card to Team Lead
        await sendIDCardEmail({ 
            name: registrationEntry.leadName, 
            email: registrationEntry.leadEmail 
        }, registrationEntry, qrImage);

        // C. Send Individual ID Card to each Team Member
        if(registrationEntry.members && registrationEntry.members.length > 0) {
            for(const member of registrationEntry.members) {
                await sendIDCardEmail({ 
                    name: member.name, 
                    email: member.email 
                }, registrationEntry, qrImage);
            }
        }
        
        res.json({ success: true, registrationId: regId });
    } catch (err) {
        console.error("Verification Error:", err);
        res.status(500).json({ error: 'Finalization failed' });
    }
});

/**
 * RECEIPT MAILER: Financial confirmation for the Team Lead
 */
async function sendReceiptEmail(data) {
    const receiptHtml = `
    <div style="background-color: #f8fafc; padding: 40px 10px; font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; -webkit-font-smoothing: antialiased;">
    <!-- Main Card Container -->
    <div style="max-width: 500px; margin: 0 auto; background-color: #ffffff; border-radius: 16px; overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06); border: 1px solid #e2e8f0;">
        
        <!-- Header Section -->
        <div style="background-color: #0f172a; padding: 40px 30px; text-align: center;">
            <div style="background-color: #10b981; width: 48px; height: 48px; border-radius: 24px; margin: 0 auto 16px; display: inline-block; line-height: 48px; vertical-align: middle;">
                <span style="color: #ffffff; font-size: 24px; font-weight: bold;">✓</span>
            </div>
            <h1 style="margin: 0; font-size: 12px; text-transform: uppercase; letter-spacing: 2px; color: #94a3b8; font-weight: 700;">Payment Successful</h1>
            <div style="font-size: 38px; font-weight: 800; margin-top: 8px; color: #ffffff;">₹${data.amount}</div>
        </div>

        <!-- Body Section -->
        <div style="padding: 32px;">
            <p style="font-size: 16px; color: #334155; margin: 0 0 24px 0; line-height: 1.6;">
                Hi <strong style="color: #0f172a;">${data.leadName}</strong>,<br>
                Your registration for <span style="font-weight: 600; color: #0f172a;">${data.eventName}</span> has been confirmed. We've received your payment and secured your spot.
            </p>

            <!-- Details Table (Using table for email compatibility inside divs) -->
            <div style="border-top: 1px dashed #e2e8f0; border-bottom: 1px dashed #e2e8f0; padding: 20px 0; margin-bottom: 24px;">
                <table border="0" cellpadding="0" cellspacing="0" width="100%">
                    <tr>
                        <td style="padding: 6px 0; color: #64748b; font-size: 12px; text-transform: uppercase; font-weight: 600;">Status</td>
                        <td style="padding: 6px 0; text-align: right;">
                            <span style="background-color: #ecfdf5; color: #059669; padding: 4px 10px; border-radius: 9999px; font-size: 11px; font-weight: 700; text-transform: uppercase;">Paid</span>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding: 6px 0; color: #64748b; font-size: 12px; text-transform: uppercase; font-weight: 600;">Registration ID</td>
                        <td style="padding: 6px 0; text-align: right; color: #0f172a; font-size: 14px; font-weight: 600;">${data.registrationId}</td>
                    </tr>
                    <tr>
                        <td style="padding: 6px 0; color: #64748b; font-size: 12px; text-transform: uppercase; font-weight: 600;">Transaction ID</td>
                        <td style="padding: 6px 0; text-align: right; color: #0f172a; font-size: 14px; font-weight: 600;">${data.paymentId}</td>
                    </tr>
                </table>
            </div>

            <!-- Note Box -->
            <div style="background-color: #f1f5f9; border-left: 4px solid #0f172a; padding: 16px; border-radius: 8px;">
                <p style="margin: 0; font-size: 13px; color: #475569; line-height: 1.5;">
                    <strong style="color: #0f172a;">Note:</strong> Individual ID cards have been sent to your team members' registered email addresses separately.
                </p>
            </div>
        </div>
    </div>

    <!-- Footer / Attribution -->
    <div style="text-align: center; margin-top: 30px;">
        <p style="margin: 0; font-size: 12px; color: #94a3b8; font-weight: 500;">
            This system was developed by 
            <a href="https://xetasolutions.in" style="color: #64748b; text-decoration: none; font-weight: 700;">Xeta Solutions</a>
        </p>
        <p style="margin: 5px 0 0 0; font-size: 11px; color: #cbd5e1;">
            <a href="https://xetasolutions.in" style="color: #3b82f6; text-decoration: underline;">xetasolutions.in</a>
        </p>
    </div>
</div>`;

    try {
        await ses.sendEmail({
            Source: 'events@xetasolutions.in',
            Destination: { ToAddresses: [data.leadEmail] },
            Message: {
                Subject: { Data: `Receipt: Registration for ${data.eventName}` },
                Body: { Html: { Data: receiptHtml } }
            }
        }).promise();
    } catch (err) { console.error("Receipt Mail Error:", err.message); }
}

/**
 * ID CARD MAILER: Individual pass for each participant
 */
async function sendIDCardEmail(recipient, data, qrImage) {
    const idHtml = `
   <div style="background-color: #f8fafc; padding: 40px 10px; font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; -webkit-font-smoothing: antialiased;">
    <!-- Main Pass Container -->
    <div style="max-width: 500px; margin: 0 auto; background-color: #ffffff; border-radius: 20px; overflow: hidden; box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05); border: 1px solid #e2e8f0;">
        
        <!-- Header Section -->
        <div style="background-color: #0f172a; padding: 40px 30px; text-align: center;">
            <h1 style="margin: 0; font-size: 13px; text-transform: uppercase; letter-spacing: 3px; color: #94a3b8; font-weight: 700;">Official Entry Pass</h1>
            <div style="font-size: 24px; font-weight: 800; margin-top: 10px; color: #fbbf24;">${data.eventName}</div>
        </div>

        <!-- Body Section -->
        <div style="padding: 40px 32px; text-align: center;">
            <p style="font-size: 16px; color: #334155; margin: 0 0 30px 0; line-height: 1.6;">
                Hi <strong style="color: #0f172a;">${recipient.name}</strong>,<br>
                Here is your digital entry pass for the event.
            </p>

            <!-- Registration ID Section (QR Removed) -->
            <div style="margin: 0 auto 30px auto; width: 260px; padding: 24px; background-color: #f8fafc; border-radius: 16px; border: 1px solid #e2e8f0; border-style: dashed;">
                <div style="color: #64748b; font-size: 11px; text-transform: uppercase; letter-spacing: 2px; margin-bottom: 8px; font-weight: 700;">Registration ID</div>
                <div style="font-family: 'Courier New', Courier, monospace; font-size: 22px; font-weight: 800; color: #0f172a; letter-spacing: 2px;">
                    ${data.registrationId}
                </div>
            </div>

            <!-- Action Button -->
            <div style="margin-bottom: 30px;">
                <a href="https://events-lbrce.in/id-card.html?id=${data.registrationId}&email=${recipient.email}" 
                   style="background-color: #fbbf24; color: #0f172a; padding: 16px 32px; border-radius: 12px; text-decoration: none; font-weight: 800; display: inline-block; font-size: 14px; letter-spacing: 0.5px; box-shadow: 0 4px 6px -1px rgba(251, 191, 36, 0.3);">
                    DOWNLOAD FULL ID CARD
                </a>
            </div>

            <!-- Verification Note -->
            <div style="background-color: #f1f5f9; padding: 16px; border-radius: 12px; border: 1px solid #e2e8f0;">
                <p style="margin: 0; font-size: 12px; color: #64748b; line-height: 1.5;">
                    <strong style="color: #475569;">Verification:</strong> Please present your Registration ID at the entrance. A valid government ID may be required for verification.
                </p>
            </div>
        </div>
    </div>

    <!-- Footer / Attribution -->
    <div style="text-align: center; margin-top: 30px;">
        <p style="margin: 0; font-size: 12px; color: #94a3b8; font-weight: 500;">
            This system was developed by 
            <a href="https://xetasolutions.in" style="color: #64748b; text-decoration: none; font-weight: 700;">Xeta Solutions</a>
        </p>
    </div>
</div>`;

    try {
        await ses.sendEmail({
            Source: 'events@xetasolutions.in',
            Destination: { ToAddresses: [recipient.email] },
            Message: {
                Subject: { Data: `Your Entry Pass: ${data.eventName}` },
                Body: { Html: { Data: idHtml } }
            }
        }).promise();
    } catch (err) { console.error("ID Card Mail Error:", err.message); }
}

app.post('/api/register/free', async (req, res) => {
    const { registrationData } = req.body;
    if (parseFloat(registrationData.amount) > 0) {
        return res.status(400).json({ error: 'Payment required for this event.' });
    }
    await finalizeRegistration(registrationData, 'FREE_ENTRY', res);
});

async function finalizeRegistration(data, payId, res) {
    const regId = `REG-${Date.now()}`;
    try {
        // The QR now points to the verification API endpoint
        const qrContent = `https://events-lbrce.in/api/verify-attendance/${regId}`;
        const qrImage = await QRCode.toDataURL(qrContent);
        
        await dynamo.put({
            TableName: 'LBRCE_Registrations',
            Item: { 
                registrationId: regId, 
                paymentId: payId, 
                ...data, 
                attendance: false, 
                timestamp: new Date().toISOString() 
            }
        }).promise();

        await sendConfirmationMails(data, qrImage, regId);
        res.json({ success: true, registrationId: regId });
    } catch (err) {
        res.status(500).json({ error: 'Save failed' });
    }
}

async function sendConfirmationMails(data, qrImage, regId) {
    const participants = [
        { name: data.leadName, email: data.leadEmail },
        ...data.members.map(m => ({ name: m.name, email: m.email }))
    ];

    const baseUrl = `https://events-lbrce.in`; 

    for (const person of participants) {
        try {
            await ses.sendEmail({
                Destination: { ToAddresses: [person.email] },
                Message: {
                    Body: { Html: { Data: `
                       <div style="margin: 0; padding: 40px 10px; background-color: #f4f7f9; font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
    <!-- Main Email Card -->
    <table role="presentation" width="100%" border="0" cellspacing="0" cellpadding="0" style="max-width: 500px; background-color: #ffffff; border-radius: 16px; margin: auto; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.08); border-collapse: collapse;">
        
        <!-- Header/Logo Area -->
        <tr>
            <td align="center" style="padding: 40px 40px 20px 40px;">
                <img src="https://res.cloudinary.com/djdwpjm7x/image/upload/v1769925973/events_lbrce_logo_sefvzr.png" 
                     alt="LBRCE Logo" 
                     width="90" 
                     style="display: block; outline: none; border: none; text-decoration: none;"
                     onerror="this.src='https://via.placeholder.com/90?text=LBRCE'">
            </td>
        </tr>

        <!-- Body Content -->
        <tr>
            <td align="center" style="padding: 0 40px;">
                <h2 style="color: #003366; font-size: 24px; margin: 0; font-weight: 700; letter-spacing: 0.5px; text-transform: uppercase;">
                    Registration Confirmed
                </h2>
                <p style="color: #556677; font-size: 16px; line-height: 24px; margin: 20px 0 25px 0;">
                    Hi <strong>${person.name}</strong>, you are officially confirmed for <strong>${data.eventName}</strong>. We look forward to seeing you!
                </p>
                
                <!-- QR Code Section -->
                

                <p style="color: #64748b; font-size: 13px; margin: 0 0 25px 0; line-height: 1.5;">
                    <span style="color: #FFB800; font-weight: bold;">Note:</span> Present this QR code at the entrance for attendance verification.
                </p>

                <!-- Action Button -->
                <div style="margin-bottom: 35px;">
                    <a href="${baseUrl}/id-card.html?id=${regId}&email=${encodeURIComponent(person.email)}" target="_blank" style="background-color: #FFB800; color: #003366; padding: 18px 30px; border-radius: 12px; text-decoration: none; font-weight: 800; display: inline-block; font-size: 14px; letter-spacing: 1px; box-shadow: 0 4px 6px rgba(255, 184, 0, 0.2);">
                        DOWNLOAD ID CARD
                    </a>
                </div>
            </td>
        </tr>

        <!-- Footer Area -->
        <tr>
            <td align="center" style="padding: 30px 40px; background-color: #f8fafc; border-top: 1px solid #edf2f7;">
                <p style="color: #64748b; font-size: 12px; line-height: 18px; margin: 0;">
                    Need help? Reply to this email or visit the help desk at the event venue.
                </p>
                <p style="color: #003366; font-size: 11px; font-weight: 600; margin-top: 15px; letter-spacing: 0.5px; line-height: 1.5;">
                    This System was Designed & developed by <br>
                    <a href="https://xetasolutions.in" target="_blank" style="color: #FFB800; text-decoration: none; border-bottom: 1px solid #FFB800;">Xeta Tech Solutions</a>
                </p>
            </td>
        </tr>
    </table>

    <!-- Bottom Spacing -->
    <table role="presentation" width="100%" border="0" cellspacing="0" cellpadding="0" style="max-width: 500px; margin: auto;">
        <tr>
            <td align="center" style="padding-top: 20px;">
                <p style="color: #cbd5e1; font-size: 11px; margin: 0;">
                    &copy; 2024 LBRCE Events Portal. All rights reserved.
                </p>
            </td>
        </tr>
    </table>
</div>` } },
                    Subject: { Data: `LBRCE Confirmation: ${data.eventName}` }
                },
                Source: process.env.SES_EMAIL || 'events@xetasolutions.in'
            }).promise();
            console.log(`Mail successfully sent to ${person.email}`);
        } catch (mailErr) {
            console.error(`Mail failed for ${person.email}:`, mailErr.message);
        }
    }
}

// 7. ADMIN STATS & OPERATIONS
app.get('/api/admin/stats', isAdmin, async (req, res) => {
    try {
        const regs = await dynamo.scan({ TableName: 'LBRCE_Registrations' }).promise();
        const events = await dynamo.scan({ TableName: 'LBRCE_Events' }).promise();
        
        // UPDATED: Calculate revenue using baseAmount (Event Price) only, ignoring platform fees.
        const totalRevenue = regs.Items.reduce((acc, curr) => acc + parseFloat(curr.baseAmount || curr.amount || 0), 0);
        
        res.json({ 
            registrationCount: regs.Count, 
            revenue: totalRevenue, 
            eventCount: events.Count 
        });
    } catch (err) { res.status(500).json({ error: 'Stats error' }); }
});

app.get('/api/admin/registrations', isAdmin, async (req, res) => {
    try {
        const data = await dynamo.scan({ TableName: 'LBRCE_Registrations' }).promise();
        res.json(data.Items);
    } catch (err) { res.status(500).json({ error: 'Fetch failed' }); }
});

app.post('/api/admin/mark-attendance', isAdmin, async (req, res) => {
    const { registrationId } = req.body;
    const params = {
        TableName: 'LBRCE_Registrations',
        Key: { registrationId },
        UpdateExpression: "set attendance = :a",
        ExpressionAttributeValues: { ":a": true }
    };
    try {
        await dynamo.update(params).promise();
        res.json({ success: true });
    } catch (err) { res.status(500).json({ error: 'Attendance update failed' }); }
});

// 1. Certificate Issuance Endpoint
app.post('/api/admin/certificates/issue', isAdmin, async (req, res) => {
    // We must receive config (x, y, fs) from the frontend
    const { recipients, templateUrl, config, eventName } = req.body;
    
    // Use your actual production domain here once deployed
    const baseUrl = `https://events-lbrce.in`; 
    
    for (const student of recipients) {
        try {
            // Construct the Smart Link with ALL parameters
            const dynamicLink = `${baseUrl}/certificate.html?` + 
                `name=${encodeURIComponent(student.name)}&` +
                `template=${encodeURIComponent(templateUrl)}&` +
                `x=${config.x || 500}&` +
                `y=${config.y || 500}&` +
                `fs=${config.fs || 60}&` +
                `event=${encodeURIComponent(eventName || 'Event')}`;

            await ses.sendEmail({
                Destination: { ToAddresses: [student.email] },
                Message: {
                    Body: { Html: { Data: `
                        <div style="margin: 0; padding: 40px 10px; background-color: #f4f7f9; font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
    <!-- Main Email Card -->
    <table role="presentation" width="100%" border="0" cellspacing="0" cellpadding="0" style="max-width: 500px; background-color: #ffffff; border-radius: 16px; margin: auto; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.08); border-collapse: collapse;">
        
        <!-- Header/Logo Area -->
        <tr>
            <td align="center" style="padding: 40px 40px 20px 40px;">
                <img src="https://res.cloudinary.com/djdwpjm7x/image/upload/v1769925973/events_lbrce_logo_sefvzr.png" 
                     alt="LBRCE Logo" 
                     width="90" 
                     style="display: block; outline: none; border: none; text-decoration: none;"
                     onerror="this.src='https://via.placeholder.com/90?text=LBRCE'">
            </td>
        </tr>

        <!-- Body Content -->
        <tr>
            <td align="center" style="padding: 0 40px;">
                <h2 style="color: #003366; font-size: 24px; margin: 0; font-weight: 700; letter-spacing: 0.5px; text-transform: uppercase;">
                    Congratulations!
                </h2>
                <p style="color: #556677; font-size: 16px; line-height: 24px; margin: 20px 0 30px 0;">
                    Hi <strong>${student.name}</strong>, your certificate for <strong>${eventName}</strong> is ready and verified.
                </p>
                
                <!-- Action Button -->
                <div style="margin-bottom: 30px;">
                    <a href="${dynamicLink}" target="_blank" style="background-color: #FFB800; color: #003366; padding: 18px 30px; border-radius: 12px; text-decoration: none; font-weight: 800; display: inline-block; font-size: 14px; letter-spacing: 1px; box-shadow: 0 4px 6px rgba(255, 184, 0, 0.2);">
                        VIEW & DOWNLOAD CERTIFICATE
                    </a>
                </div>

                <p style="color: #94a3b8; font-size: 11px; margin: 0 0 40px 0; text-transform: uppercase; letter-spacing: 1px; font-weight: 600;">
                    <span style="font-size: 14px; margin-right: 4px; color: #10b981;">✓</span>
                    Verified by LBRCE Authority
                </p>
            </td>
        </tr>

        <!-- Footer Area -->
        <tr>
            <td align="center" style="padding: 30px 40px; background-color: #f8fafc; border-top: 1px solid #edf2f7;">
                <p style="color: #64748b; font-size: 12px; line-height: 18px; margin: 0;">
                    This certificate is an official record of your achievement. You can always access it through your portal dashboard.
                </p>
                <p style="color: #003366; font-size: 11px; font-weight: 600; margin-top: 15px; letter-spacing: 0.5px; line-height: 1.5;">
                    This System was Designed & developed by <br>
                    <a href="https://xetasolutions.in" target="_blank" style="color: #FFB800; text-decoration: none; border-bottom: 1px solid #FFB800;">Xeta Tech Solutions</a>
                </p>
            </td>
        </tr>
    </table>

    <!-- Bottom Spacing -->
    <table role="presentation" width="100%" border="0" cellspacing="0" cellpadding="0" style="max-width: 500px; margin: auto;">
        <tr>
            <td align="center" style="padding-top: 20px;">
                <p style="color: #cbd5e1; font-size: 11px; margin: 0;">
                    &copy; 2024 LBRCE Events Portal. All rights reserved.
                </p>
            </td>
        </tr>
    </table>
</div>` } },
                    Subject: { Data: `Certificate of Participation: ${eventName}` }
                },
                Source: 'events@xetasolutions.in'
            }).promise();
        } catch (e) { console.error("Mail Error:", e.message); }
    }
    res.json({ success: true, count: recipients.length });
});

// --- UPDATED OTP & STATUS ENDPOINTS ---

// 1. Send OTP to Lead Email
app.post('/api/status/send-otp', async (req, res) => {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'Email is required.' });

    try {
        const regs = await dynamo.scan({ TableName: 'LBRCE_Registrations' }).promise();
        
        // FIX: Added 'r.leadEmail &&' to prevent crash if a record is missing the email field
        const user = regs.Items.find(r => r.leadEmail && r.leadEmail.toLowerCase() === email.toLowerCase());
        
        if (!user) {
            return res.status(404).json({ error: 'No registration found for this Lead Email.' });
        }

        const otp = Math.floor(100000 + Math.random() * 900000).toString();
        await dynamo.put({
            TableName: 'LBRCE_OTPs',
            Item: { 
                email: email.toLowerCase(), 
                otp: otp, 
                expiresAt: Math.floor(Date.now() / 1000) + 600 
            }
        }).promise();

        // Prestige Email Template
        const prestigeMailHtml = `
        <div style="margin: 0; padding: 0; background-color: #F8FAFC; font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;">
            <table role="presentation" width="100%" border="0" cellspacing="0" cellpadding="0">
                <tr>
                    <td align="center" style="padding: 40px 10px;">
                        <table role="presentation" width="100%" border="0" cellspacing="0" cellpadding="0" style="max-width: 500px; background-color: #ffffff; border-radius: 40px; overflow: hidden; box-shadow: 0 20px 50px rgba(0,45,90,0.1); border: 1px solid #ffffff;">
                            <!-- Header -->
                            <tr>
                                <td align="center" style="padding: 50px 40px 30px 40px; background: linear-gradient(135deg, #002D5A 0%, #001A33 100%);">
                                    <img src="https://res.cloudinary.com/djdwpjm7x/image/upload/v1769925973/events_lbrce_logo_sefvzr.png" alt="LBRCE" width="80" style="margin-bottom: 20px;">
                                    <h2 style="color: #FFB800; font-size: 14px; margin: 0; font-weight: 800; letter-spacing: 4px; text-transform: uppercase;">Identity Verification</h2>
                                </td>
                            </tr>

                            <!-- Body -->
                            <tr>
                                <td align="center" style="padding: 40px 40px;">
                                    <p style="color: #64748B; font-size: 15px; line-height: 24px; margin: 0 0 30px 0; font-weight: 500;">
                                        Enter the secure authorization key below to access your <strong>LBRCE Event Dashboard</strong>.
                                    </p>
                                    
                                    <!-- OTP Box -->
                                    <div style="background-color: #F1F5F9; border-radius: 24px; padding: 30px; margin-bottom: 30px;">
                                        <h1 style="color: #002D5A; font-size: 48px; letter-spacing: 8px; margin: 0; font-weight: 900; font-family: 'Courier New', Courier, monospace;">
                                            ${otp}
                                        </h1>
                                    </div>

                                    <table role="presentation" border="0" cellspacing="0" cellpadding="0">
                                        <tr>
                                            <td align="center" style="border-radius: 12px; background-color: #FFFBEB; padding: 10px 20px; border: 1px solid #FEF3C7;">
                                                <p style="color: #B45309; font-size: 11px; margin: 0; font-weight: 800; text-transform: uppercase; letter-spacing: 1px;">
                                                    Expires in 10 minutes
                                                </p>
                                            </td>
                                        </tr>
                                    </table>
                                </td>
                            </tr>

                            <!-- Footer -->
                            <tr>
                                <td align="center" style="padding: 30px 40px; background-color: #F8FAFC; border-top: 1px solid #F1F5F9;">
                                    <p style="color: #94A3B8; font-size: 10px; line-height: 18px; margin: 0; font-weight: 700; text-transform: uppercase; letter-spacing: 1px;">
                                        LBRCE Events Portal &copy; 2026
                                    </p>
                                    <p style="color: #CBD5E1; font-size: 9px; margin-top: 10px; font-weight: 600;">
                                        Secure Transmission by Xeta Tech Solutions
                                    </p>
                                </td>
                            </tr>
                        </table>
                    </td>
                </tr>
            </table>
        </div>`;

        await ses.sendEmail({
            Destination: { ToAddresses: [email] },
            Message: {
                Body: { Html: { Data: prestigeMailHtml } },
                Subject: { Data: `Verification Key: ${otp} for LBRCE Portal` }
            },
            Source: 'events@xetasolutions.in' 
        }).promise();

        res.json({ success: true });
    } catch (err) {
        console.error("OTP Send Error:", err);
        res.status(500).json({ error: 'Internal Server Error' });
    }
});

// 2. Verify OTP & Return User Data
app.post('/api/status/verify-otp', async (req, res) => {
    const { email, otp } = req.body;
    try {
        const result = await dynamo.get({ TableName: 'LBRCE_OTPs', Key: { email: email.toLowerCase() } }).promise();
        const stored = result.Item;

        if (!stored || stored.otp !== otp) {
            return res.status(401).json({ error: 'Invalid or expired code.' });
        }

        await dynamo.delete({ TableName: 'LBRCE_OTPs', Key: { email: email.toLowerCase() } }).promise();

        const regs = await dynamo.scan({ TableName: 'LBRCE_Registrations' }).promise();
        
        // FIX: Added 'r.leadEmail &&' here as well for consistency
        const userData = regs.Items.find(r => r.leadEmail && r.leadEmail.toLowerCase() === email.toLowerCase());
        
        res.json({ success: true, data: userData });
    } catch (err) {
        console.error("OTP Verify Error:", err);
        res.status(500).json({ error: 'Authorization failure.' });
    }
});

// --- MASTER DATA REGISTRY (REFINED) ---

// 1. ADMIN SYNC (GET ALL)
app.get('/api/master-data', async (req, res) => {
    try {
        const result = await dynamo.get({ TableName: 'LBRCE_Settings', Key: { settingId: 'MasterLists' } }).promise();
        res.json(result.Item || { colleges: [], departments: [] });
    } catch (err) { res.status(500).json({ error: 'Public registry fetch failed' }); }
});

// 2. ADMIN GET (For admin_master_data.html - With isAdmin check)
app.get('/api/admin/master-data', isAdmin, async (req, res) => {
    try {
        const result = await dynamo.get({ TableName: 'LBRCE_Settings', Key: { settingId: 'MasterLists' } }).promise();
        res.json(result.Item || { colleges: [], departments: [] });
    } catch (err) { res.status(500).json({ error: 'Admin registry fetch failed' }); }
});

// 3. ADMIN ADD ITEM
app.post('/api/admin/master-data/add', isAdmin, async (req, res) => {
    const { type, value } = req.body;
    try {
        const result = await dynamo.get({ TableName: 'LBRCE_Settings', Key: { settingId: 'MasterLists' } }).promise();
        let data = result.Item || { colleges: [], departments: [], settingId: 'MasterLists' };
        if (!data[type].includes(value)) {
            data[type].push(value);
            await dynamo.put({ TableName: 'LBRCE_Settings', Item: data }).promise();
        }
        res.json({ success: true, list: data[type] });
    } catch (err) { res.status(500).json({ error: 'Add failed' }); }
});

// 4. ADMIN REMOVE ITEM
app.post('/api/admin/master-data/remove', isAdmin, async (req, res) => {
    const { type, value } = req.body;
    try {
        const result = await dynamo.get({ TableName: 'LBRCE_Settings', Key: { settingId: 'MasterLists' } }).promise();
        let data = result.Item;
        if (data) {
            data[type] = data[type].filter(item => item !== value);
            await dynamo.put({ TableName: 'LBRCE_Settings', Item: data }).promise();
        }
        res.json({ success: true, list: data ? data[type] : [] });
    } catch (err) { res.status(500).json({ error: 'Remove failed' }); }
});

// 5. ADMIN BATCH UPDATE (Excel)
app.post('/api/admin/master-data/batch', isAdmin, async (req, res) => {
    const { type, items } = req.body;
    try {
        const result = await dynamo.get({ TableName: 'LBRCE_Settings', Key: { settingId: 'MasterLists' } }).promise();
        let data = result.Item || { colleges: [], departments: [], settingId: 'MasterLists' };
        data[type] = items;
        await dynamo.put({ TableName: 'LBRCE_Settings', Item: data }).promise();
        res.json({ success: true, list: data[type] });
    } catch (err) { res.status(500).json({ error: 'Batch update failed' }); }
});

// CHECK FOR DUPLICATE REGISTRATIONS
// 7. DUPLICATE CHECK ENDPOINT
app.post('/api/check-duplicates', async (req, res) => {
    const { identifiers } = req.body; 
    try {
        const data = await dynamo.scan({ TableName: 'LBRCE_Registrations' }).promise();
        const existingRegistrations = data.Items;

        // Ensure identifiers is an array and normalize it to prevent errors
        const normalizedIdentifiers = (identifiers || []).map(i => i?.toLowerCase().trim());

        for (const reg of existingRegistrations) {
            // 1. Check Captain (Using Optional Chaining ?. to handle undefined fields safely)
            const leadEmail = reg.leadEmail?.toLowerCase();
            const leadRoll = reg.leadRoll?.toLowerCase();

            if ((leadEmail && normalizedIdentifiers.includes(leadEmail)) || 
                (leadRoll && normalizedIdentifiers.includes(leadRoll))) {
                return res.json({ 
                    exists: true, 
                    conflict: normalizedIdentifiers.includes(leadEmail) ? reg.leadEmail : reg.leadRoll 
                });
            }

            // 2. Check all team members
            if (reg.members && Array.isArray(reg.members)) {
                for (const mem of reg.members) {
                    const memEmail = mem.email?.toLowerCase();
                    const memRoll = mem.roll?.toLowerCase();

                    if ((memEmail && normalizedIdentifiers.includes(memEmail)) || 
                        (memRoll && normalizedIdentifiers.includes(memRoll))) {
                        return res.json({ 
                            exists: true, 
                            conflict: normalizedIdentifiers.includes(memEmail) ? mem.email : mem.roll 
                        });
                    }
                }
            }
        }

        res.json({ exists: false });
    } catch (err) {
        // Detailed logging to identify issues in the future
        console.error("Duplicate Check Error:", err);
        res.status(500).json({ error: 'System integrity check failed' });
    }
});

app.get('/api/config', (req, res) => {
    // Only send the public Key ID, never the Secret
    res.json({ razorpay_key_id: process.env.RAZORPAY_KEY_ID });
});


const PORT = process.env.PORT || 3000;

app.listen(PORT, () => console.log(`🚀 LBRCE Server Live on Port ${PORT}`));




