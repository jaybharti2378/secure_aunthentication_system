# Testing notes

This starter repository includes API routes intended to be tested with pytest and Flask's test client.

For an isolated test environment, create a temporary PostgreSQL database and set `DATABASE_URL` to that database before importing the app. Add tests for:
- successful and duplicate registration
- login success and invalid credentials
- protected `/api/auth/me`
- refresh-token rotation and replay rejection
- logout revocation
