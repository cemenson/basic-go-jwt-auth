A basic authentication API using JWTs written in Go!

# Features

- JWT based authentication with access and refresh tokens
- Redis JWT token caching
- Mongodb credential storage
- SHA-256 hashed and salted passwords
- Mux middleware for protecting secure endpoints

# To run

- Ensure you have running instances of Redis and Mongodb
- Update the host variables (defaults to localhost)
- `go run main.go`

# To do

- Move environmental variable outside of code


# API

### /login
- Method: `POST`
- Body: `{"id": "<USERNAME>", "password": "<PASSWORD>"}`

### /logout
- Method: `POST`
- Headers: `Authorization: <JWT>`

### /register
- Method: `POST`
- Body: `{"email": "<EMAIL>", "password": "<PASSWORD>"}`

### /account
- Method: `GET`
- Headers: `Authorization: <JWT>`

### /token/refresh
- Method: `POST`
- Headers: `Authorization: <JWT>`
- Body: `{"refresh_token": "<REFRESH_TOKEN>"}`

## Reasons for this project

1) To teach myself Go
2) To serve as a basic template for future projects needing an authentication service
