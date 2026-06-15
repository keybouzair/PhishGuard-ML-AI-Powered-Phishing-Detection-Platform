# SQLite -> PostgreSQL Migration Approach

## Goal
Move runtime storage from SQLite to PostgreSQL without downtime and without breaking API contracts.

## Steps
1. Provision PostgreSQL and create database.
2. Apply schema from `schema.sql`.
3. Export SQLite data as CSV per table (`users`, `url_checks`, `blocklist`, `activity_log`).
4. Import into PostgreSQL with staging tables.
5. Transform fields:
   - map `users.password` -> `users.password_hash`
   - map integer `is_active` -> boolean
6. Verify row counts and random sample checks.
7. Deploy app with `DATABASE_URL` pointing to PostgreSQL.
8. Keep SQLite as read-only rollback snapshot for 7 days.

## Validation Checklist
- [ ] API login works
- [ ] URL checks persist
- [ ] blocklist add/remove works
- [ ] dashboard stats match baseline
- [ ] activity logging works
