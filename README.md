# Chirpy

This project is a Twitter like application. Chirpy is a guide project created through a [boot.dev](https://www.boot.dev/courses/learn-web-servers) course.

The project is a CRUD REST Api write in go using [jwt-go](https://pkg.go.dev/github.com/golang-jwt/jwt/v5) library to manage authentifaction.

## Insttall

The server need golang install to run.
`sudo apt-get update && sudo apt-get -y install golang-go` 

Create a .env file
```
# ./.env

JWT_SECRET=<CHANGE_THIS_PART>
POLKA_API_KEY=<CHANGE_THIS_PART>
```

## Usage

Without change in main.go the webserver for the API will live at port `8080`:
`go build -o out && ./out`



