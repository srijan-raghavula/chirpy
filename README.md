# Chirpy web server

## What is chirpy?

    Chirpy is a guided web server project from [boot.dev](https://www.boot.dev/courses/learn-web-servers) in an attempt to learn web server and how to make one using Go.

## What does chirpy do?

    Chirpy is similar to Twitter/X. Microblogs limited to 140 characters are called chirps.

## What can users do?

- Create account (POST /api/users)
- Update credentials (PUT /api/users)
- Login (POST /api/login)
- Post Chirps (POST /api/chirps)
- Remove Chirps (DELETE /api/chirps/{chirpID})
- Get single chirp (GET /api/chirps/{chirpID})
- Get all chirps (GET /api/chirps)

*refer main.go for more on endpoints*

## Where does it serve?

    For now, it's hosted locally at :8080
