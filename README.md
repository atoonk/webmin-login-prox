# Webmin Login Proxy

This Webmin login proxy handles the authentication for users, so they don't need to know the actual Webmin password. It acts as a credential broker proxy, simplifying the login process.

## Features

- **Credential Management**: Manages Webmin credentials and handles login on behalf of users.
- **Session Handling**: Creates and manages sessions for authenticated users.
- **Reverse Proxy**: Forwards requests to the Webmin server while managing authentication.

## Warning

**Security Warning:** This proxy effectively opens up your Webmin to anyone on the internet. It is highly recommended to place this proxy behind an authenticating proxy like [Border0](https://border0.com) or another authentication mechanism to secure access. 
It's also recommended to have the Proxy listen on localhost only.

## Usage

### Configuration

Create a `config.json` file with the following structure:

```json
{
  "webminURL": "https://your-webmin-url:10000",
  "listenAddr": "127.0.0.1:8443",
  "username": "your-webmin-username",
  "password": "your-webmin-password"
}
```

### Creating PEM Files
To create `cert.pem` and `key.pem` files for SSL/TLS, you can use the following OpenSSL commands:
```
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout key.pem -out cert.pem
```
Follow the prompts to enter information about your organization. These files are necessary for HTTPS.


### Running the Proxy
* Ensure you have cert.pem and key.pem for SSL/TLS.
* Run the proxy:
```bash
go run main.go
```

The proxy server will start and listen on the address specified in `config.json`.

### Example config.json
```json
{
  "webminURL": "https://your-webmin-url:10000",
  "listenAddr": "127.0.0.1:8443",
  "username": "your-webmin-username",
  "password": "your-webmin-password"
}
```
 ## Download

Download the latest release [here](https://github.com/atoonk/webmin-login-prox/releases/latest).



