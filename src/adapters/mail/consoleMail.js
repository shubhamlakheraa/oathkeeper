/**
 * Development-only mail adapter. Prints each email to stdout in a readable,
 * copy-pasteable format. Never use in production — no email is actually sent.
 *
 * @returns {import('./MailAdapter').MailAdapter}
 */
function createConsoleMail() {
  return {
    async sendMail({ to, subject, html }) {
      console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
      console.log(`📧  TO:      ${to}`);
      console.log(`    SUBJECT: ${subject}`);
      console.log('    BODY:');
      console.log(html);
      console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    },
  };
}

module.exports = { createConsoleMail };
