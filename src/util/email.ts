import nodemailer from 'nodemailer'
import crypto from 'crypto'
import 'dotenv/config'

export function generateActivationToken() {
  return crypto.randomBytes(32).toString('hex')
}

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.MAILER_USER,
    pass: process.env.MAILER_PASS,
  },
})

export async function sendActivationEmail(userEmail: string, activationToken: string) {
  const activationLink = `${process.env.MAILER_ACTIVATION_DOMAIN}/api/users/activateUser/${activationToken}`
  const mailOptions = {
    from: process.env.MAILER_USER,
    to: userEmail,
    subject: 'Action activation',
    html: `<p>Hello,</p> <p>Click <a href="${activationLink}">here</a> to activate your account</p>`,
  }
return  await transporter.sendMail(mailOptions)
}