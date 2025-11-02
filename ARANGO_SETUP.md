# ArangoDB Setup and Fix Guide

## Issue: "not authorized to execute this request" (401 Unauthorized)

This error means ArangoDB is running, but the password in your `.env` file doesn't match the actual ArangoDB root password.

## Solutions

### Solution 1: Find Your ArangoDB Password

If ArangoDB was installed on your system, check:

```bash
# Check if there's a default password file
sudo cat /etc/arangodb3/arangod.conf | grep password

# Or check ArangoDB logs
sudo journalctl -u arangodb3 | grep -i password | tail -5

# Or check Docker container (if using Docker)
docker exec -it arangodb cat /etc/arangodb/arangod.conf | grep password
```

### Solution 2: Reset ArangoDB Root Password

#### If ArangoDB is installed on system:

```bash
# Stop ArangoDB
sudo systemctl stop arangodb3

# Start ArangoDB with authentication disabled
sudo arangod --server.authentication false

# In another terminal, connect and set password:
arangosh --server.authentication false

# Then in arangosh:
db._useDatabase("_system");
users.save("root", "your_new_password");

# Stop arangod and restart normally
# Then update .env file with the new password
```

#### If ArangoDB is in Docker:

```bash
# Stop the container
docker stop <container_id>

# Start with authentication disabled
docker run -it --rm -p 8529:8529 arangodb/arangodb arangosh --server.endpoint tcp://0.0.0.0:8529

# Or recreate container with new password
docker run -d -p 8529:8529 \
  -e ARANGO_ROOT_PASSWORD=your_new_password \
  --name arangodb \
  arangodb

# Then update .env:
# ARANGO_PASSWORD=your_new_password
```

### Solution 3: Use Default/Empty Password

If ArangoDB was installed without a password:

```bash
# Check if empty password works
curl -u root: http://localhost:8529/_api/version

# If it works, update .env:
# ARANGO_PASSWORD=
```

### Solution 4: Create New User with Specific Password

Access ArangoDB Web UI:
1. Open browser: http://localhost:8529
2. Login with root (try empty password or known password)
3. Go to Users tab
4. Create new user or change root password
5. Update `.env` file

## Quick Fix Steps

1. **Check current ArangoDB password:**
   ```bash
   # Try empty password
   curl -u root: http://localhost:8529/_api/version
   
   # Or try common defaults
   curl -u root:test http://localhost:8529/_api/version
   curl -u root:root http://localhost:8529/_api/version
   ```

2. **Once you find the correct password, update .env:**
   ```bash
   nano .env
   # Set: ARANGO_PASSWORD=actual_password_here
   ```

3. **Test the connection:**
   ```bash
   node bin/cyber-agent init
   ```

## Install ArangoDB (if not installed)

### Ubuntu/Debian:
```bash
# Add repository
curl -OL https://download.arangodb.com/arangodb39/DEBIAN/Release.key
sudo apt-key add - < Release.key
echo 'deb https://download.arangodb.com/arangodb39/DEBIAN/ /' | sudo tee /etc/apt/sources.list.d/arangodb.list
sudo apt-get update

# Install
sudo apt-get install arangodb3

# Set root password during installation
# Or set it later:
sudo systemctl start arangodb3
sudo arango-secure-installation
```

### Docker:
```bash
docker run -d \
  --name arangodb \
  -p 8529:8529 \
  -e ARANGO_ROOT_PASSWORD=mySecurePassword \
  arangodb/arangodb:latest
```

Then update `.env`:
```
ARANGO_PASSWORD=mySecurePassword
```

## Verify Connection

After updating `.env`, test:
```bash
node bin/cyber-agent init
```

Should see: "Database and knowledge graph initialized successfully!"

