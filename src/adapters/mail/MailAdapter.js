/**
 * @typedef {Object} MailMessage
 * @property {string} to      Recipient email address.
 * @property {string} subject Email subject line.
 * @property {string} html    Full HTML body. Must contain complete, copy-pasteable URLs.
 */

/**
 * @typedef {Object} MailAdapter
 * @property {(message: MailMessage) => Promise<void>} sendMail
 *   Sends a transactional email. Implementations must not swallow errors —
 *   throw so the caller can decide whether to retry or surface the failure.
 */
