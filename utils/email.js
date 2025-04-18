const nodemailer = require('nodemailer');
require('dotenv').config();

// Log environment variables (without sensitive data)
console.log('Email Configuration Status:');
console.log('GMAIL_USER configured:', !!process.env.GMAIL_USER);
console.log('GMAIL_PASS configured:', !!process.env.GMAIL_PASS);

// Create reusable transporter object using Gmail SMTP
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false, // true for 465, false for other ports
    auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_PASS
    },
    tls: {
        rejectUnauthorized: false // Only use this in development
    }
});

// Verify connection configuration
transporter.verify((error, success) => {
    if (error) {
        console.error('SMTP connection error:', error);
    } else {
        console.log('SMTP server is ready to send messages');
    }
});

/**
 * Send status update email to user
 * @param {string} userEmail - The recipient's email address
 * @param {string} trackingId - The complaint tracking ID
 * @param {string} oldStatus - The previous status
 * @param {string} newStatus - The updated status
 * @returns {Promise} - Resolves when email is sent
 */
async function sendStatusUpdateEmail(userEmail, trackingId, oldStatus, newStatus) {
    // Input validation
    if (!userEmail || !trackingId || !oldStatus || !newStatus) {
        throw new Error('Missing required parameters for sending email');
    }

    console.log('Attempting to send email to:', userEmail);
    console.log('Email details:', { trackingId, oldStatus, newStatus });

    try {
        // Email template
        const mailOptions = {
            from: {
                name: 'Government Complaint Portal',
                address: process.env.GMAIL_USER
            },
            to: userEmail,
            subject: `Complaint Status Update - ${trackingId}`,
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e5e7eb; border-radius: 8px;">
                    <h2 style="color: #1d4ed8; margin-bottom: 20px;">Complaint Status Update</h2>
                    
                    <div style="background-color: #f3f4f6; padding: 15px; border-radius: 5px; margin: 20px 0;">
                        <p style="margin: 5px 0;"><strong>Tracking ID:</strong> ${trackingId}</p>
                        <p style="margin: 5px 0;"><strong>Previous Status:</strong> ${oldStatus}</p>
                        <p style="margin: 5px 0;"><strong>New Status:</strong> ${newStatus}</p>
                    </div>
                    
                    <p>You can track your complaint status anytime using your tracking ID.</p>
                    
                    <div style="margin-top: 30px; padding-top: 20px; border-top: 1px solid #e5e7eb;">
                        <p style="margin: 0; color: #6b7280;">Best regards,</p>
                        <p style="margin: 5px 0 0; color: #1d4ed8;">Government Complaint Portal Team</p>
                    </div>
                </div>
            `
        };

        // Send email
        const info = await transporter.sendMail(mailOptions);
        console.log('Email sent successfully:', info.messageId);
        return info;
    } catch (error) {
        console.error('Error sending email:', error);
        throw error;
    }
}

module.exports = {
    sendStatusUpdateEmail
}; 