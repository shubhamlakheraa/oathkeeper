const { Client } = require('pg');

async function main() {
  const url = process.env.DATABASE_URL;
  if (!url) {
    console.error('DATABASE_URL is not set. Did you create .env and pass --env-file=.env ?');
    process.exit(1);
  }

  const client = new Client({ connectionString: url });

  try {
    await client.connect();
    const { rows } = await client.query(
      'select current_user as user, current_database() as db, version() as version',
    );
    const info = rows[0];
    console.log('Connected.');
    console.log(`  user:    ${info.user}`);
    console.log(`  db:      ${info.db}`);
    console.log(`  version: ${info.version.split(',')[0]}`);
  } catch (err) {
    console.error('Connection failed:', err.message);
    process.exit(1);
  } finally {
    await client.end();
  }
}

main();
