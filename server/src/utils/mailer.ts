import nodemailer from 'nodemailer';

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST || 'smtp.mailtrap.io',
  port: Number(process.env.SMTP_PORT) || 2525,
  secure: process.env.SMTP_SECURE === 'true',
  auth: process.env.SMTP_USER ? {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASSWORD,
  } : undefined,
});

export const sendVerificationEmail = async (email: string, username: string, token: string, origin: string) => {
  const verifyUrl = `${origin}/api/auth/verify?token=${token}`;
  
  const mailOptions = {
    from: `"Support Quarkshield" <${process.env.SMTP_FROM || 'support@quarkshield.services'}>`,
    to: email,
    subject: 'Verify your QuarkShield Account',
    html: `
      <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0b0f19; color: #f3f4f6; padding: 40px; text-align: center; border-radius: 8px; max-width: 600px; margin: 0 auto; border: 1px solid #1e293b; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);">
        <div style="margin-bottom: 24px;">
          <span style="font-size: 28px; font-weight: 800; background: linear-gradient(135deg, #06b6d4 0%, #8b5cf6 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; letter-spacing: 0.05em;">QUARKSHIELD</span>
        </div>
        <h2 style="font-size: 20px; font-weight: 600; color: #ffffff; margin-bottom: 16px; letter-spacing: -0.025em;">Confirm your email address</h2>
        <p style="color: #9ca3af; font-size: 15px; line-height: 1.6; margin-bottom: 32px;">
          Hello ${username}, thank you for registering with QuarkShield. To activate your account and access the post-quantum risk management suite, please verify your email address.
        </p>
        <a href="${verifyUrl}" style="display: inline-block; background: linear-gradient(135deg, #06b6d4 0%, #8b5cf6 100%); color: #ffffff; font-weight: 600; font-size: 15px; padding: 12px 32px; text-decoration: none; border-radius: 6px; box-shadow: 0 4px 14px 0 rgba(6, 182, 212, 0.4);">
          Verify Email Address
        </a>
        <p style="color: #6b7280; font-size: 12px; margin-top: 32px;">
          If the button doesn't work, copy and paste this link into your browser:<br/>
          <a href="${verifyUrl}" style="color: #60a5fa; text-decoration: none; word-break: break-all;">${verifyUrl}</a>
        </p>
        <hr style="border: 0; border-top: 1px solid #1e293b; margin: 32px 0;" />
        <p style="color: #4b5563; font-size: 11px; margin: 0;">
          This is an automated security transmission. If you did not create a QuarkShield account, please ignore this email.
        </p>
      </div>
    `,
  };

  await transporter.sendMail(mailOptions);
};

export const sendPortalProvisionedEmail = async (email: string, clientName: string, portalUrl: string, dbPort: number) => {
  const mailOptions = {
    from: `"Support Quarkshield" <${process.env.SMTP_FROM || 'support@quarkshield.services'}>`,
    to: email,
    subject: 'Your QuarkShield Portal is Provisioned',
    html: `
      <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #0b0f19; color: #f3f4f6; padding: 40px; border-radius: 8px; max-width: 650px; margin: 0 auto; border: 1px solid #1e293b; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);">
        <div style="text-align: center; margin-bottom: 28px;">
          <span style="font-size: 28px; font-weight: 800; background: linear-gradient(135deg, #06b6d4 0%, #8b5cf6 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; letter-spacing: 0.05em;">QUARKSHIELD</span>
        </div>
        
        <h2 style="font-size: 22px; font-weight: 600; color: #ffffff; text-align: center; margin-bottom: 16px;">Your Dedicated Portal is Ready!</h2>
        
        <p style="color: #9ca3af; font-size: 15px; line-height: 1.6; margin-bottom: 24px; text-align: center;">
          Hello, we have successfully provisioned your isolated QuarkShield quantum-safe risk management stack. Below are your environment connection parameters and feature guide:
        </p>

        <!-- Connection Parameters Card -->
        <div style="background-color: #111827; border: 1px solid #1f2937; border-radius: 6px; padding: 20px; margin-bottom: 30px;">
          <h3 style="color: #ffffff; margin-top: 0; margin-bottom: 12px; font-size: 16px; font-weight: 600; border-bottom: 1px solid #1f2937; padding-bottom: 8px;">Environment Details</h3>
          <table style="width: 100%; border-collapse: collapse; font-size: 14px;">
            <tr>
              <td style="color: #9ca3af; padding: 6px 0; font-weight: 500;">Secure Web App Link:</td>
              <td style="padding: 6px 0; text-align: right;"><a href="${portalUrl}" style="color: #22d3ee; text-decoration: none; font-weight: 600;">${portalUrl}</a></td>
            </tr>
            <tr>
              <td style="color: #9ca3af; padding: 6px 0; font-weight: 500;">Isolated Database Port:</td>
              <td style="color: #c084fc; padding: 6px 0; text-align: right; font-family: monospace; font-weight: bold;">${dbPort}</td>
            </tr>
          </table>
        </div>

        <!-- Features & Expected Results Guide -->
        <h3 style="color: #ffffff; font-size: 16px; font-weight: 600; margin-bottom: 16px; border-bottom: 1px solid #1e293b; padding-bottom: 8px;">Feature Guide & Expected Results</h3>
        
        <div style="font-size: 14px; line-height: 1.5; color: #d1d5db; margin-bottom: 30px;">
          <!-- Feature 1 -->
          <div style="margin-bottom: 16px;">
            <strong style="color: #06b6d4;">1. Cryptographic Scan Terminal</strong>
            <p style="margin: 4px 0 0 0; color: #9ca3af;">
              <strong>How to Use:</strong> Upload SSH/PEM public keys, server configuration files (like Nginx/OpenSSH), or run a live TLS domain handshake audit.
            </p>
            <p style="margin: 2px 0 0 0; color: #e2e8f0; font-style: italic;">
              <strong>Expected Result:</strong> Immediate breakdown of key-lengths and algorithm classifications showing whether they are vulnerable to Shor's/Grover's algorithms.
            </p>
          </div>

          <!-- Feature 2 -->
          <div style="margin-bottom: 16px;">
            <strong style="color: #8b5cf6;">2. Mosca's Migration Planner</strong>
            <p style="margin: 4px 0 0 0; color: #9ca3af;">
              <strong>How to Use:</strong> Adjust variables for how long your data must remain secure (Shelf-life) and how long your systems take to upgrade (Transition time) against when a Cryptanalytically Relevant Quantum Computer will exist.
            </p>
            <p style="margin: 2px 0 0 0; color: #e2e8f0; font-style: italic;">
              <strong>Expected Result:</strong> A roadmap graph showing your organization's risk horizons and checkboxes for tracking transition milestones.
            </p>
          </div>

          <!-- Feature 3 -->
          <div style="margin-bottom: 16px;">
            <strong style="color: #10b981;">3. OPA Compliance Reports</strong>
            <p style="margin: 4px 0 0 0; color: #9ca3af;">
              <strong>How to Use:</strong> Navigate to the Compliance tab to see how scanned assets measure up to policy standards.
            </p>
            <p style="margin: 2px 0 0 0; color: #e2e8f0; font-style: italic;">
              <strong>Expected Result:</strong> Dynamic compliance percentage scores and specific policy lists evaluating assets against NIST SP 800-219, CNSA 2.0, and Executive Order 14028.
            </p>
          </div>

          <!-- Feature 4 -->
          <div style="margin-bottom: 16px;">
            <strong style="color: #ec4899;">4. AI Advisory Remediation</strong>
            <p style="margin: 4px 0 0 0; color: #9ca3af;">
              <strong>How to Use:</strong> Send questions or paste custom configuration blocks in the AI Hub.
            </p>
            <p style="margin: 2px 0 0 0; color: #e2e8f0; font-style: italic;">
              <strong>Expected Result:</strong> AI-powered step-by-step remediation scripts and secure config snippets (for Rust, Go, OpenSSH, etc.) to upgrade to quantum-safe alternatives.
            </p>
          </div>
        </div>

        <div style="text-align: center; margin-bottom: 30px;">
          <a href="${portalUrl}" style="display: inline-block; background: linear-gradient(135deg, #06b6d4 0%, #8b5cf6 100%); color: #ffffff; font-weight: 600; font-size: 15px; padding: 12px 36px; text-decoration: none; border-radius: 6px; box-shadow: 0 4px 14px 0 rgba(6, 182, 212, 0.4);">
            Access Private Dashboard
          </a>
        </div>

        <hr style="border: 0; border-top: 1px solid #1e293b; margin: 32px 0;" />
        
        <p style="color: #9ca3af; font-size: 13px; line-height: 1.5; margin: 0; text-align: center;">
          For any questions, please reply directly to this email or contact us at <a href="mailto:support@quarkshield.services" style="color: #22d3ee; text-decoration: none;">support@quarkshield.services</a>.
        </p>
      </div>
    `,
  };

  await transporter.sendMail(mailOptions);
};

