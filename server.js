// Import the 'express' framework
const express = require('express')

// Create an Express application
const app = express()

// Import the 'bcrypt' library for password hashing
const bcrypt = require('bcrypt')

// Middleware to parse incoming JSON requests
// (allows the application to accept JSON data in requests)
app.use(express.json())

// Array to store user information (in-memory, not suitable for production)
const users = []

// Endpoint to retrieve all users
app.get('/users', (req, res) => {
    res.json(users)
})

// Endpoint to create a new user with a hashed password
app.post('/users', async (req, res) => {
    try {
        // Generate a salt for password hashing
        const salt = await bcrypt.genSalt()

        // Hash the user's password with the generated salt
        const hashedPassword = await bcrypt.hash(req.body.password, 10)

        // Create a new user with the hashed password
        const user = { name: req.body.name, password: hashedPassword }

        // Add the user to the users array
        users.push(user)

        // Send a successful response with status code 201 (Created)
        res.sendStatus(201).send()
    } catch {
        // If an error occurs, send a server error response with status code 500
        res.status(500).send()
    }
})

// Endpoint for user login with password comparison
app.post('/users/login', async (req, res) => {
    // Find the user with the provided username
    const user = users.find(user => user.name === req.body.name)

    // If the user is not found, send a client error response with status code 400
    if (user == null) {
        return res.status(400).send('Cannot find user')
    }

    try {
        // Compare the provided password with the stored hashed password
        if (await bcrypt.compare(req.body.password, user.password)) {
            // If passwords match, send a success message
            res.send('Successfully Logged In!')
        } else {
            // If passwords do not match, send an invalid credentials message
            res.send('Invalid Credentials')
        }
    } catch {
        // If an error occurs, send a server error response with status code 500
        res.status(500).send()
    }
})

// Start the Express server on port 3000
app.listen(3000, () => {
    console.log('Server running on port 3000')
})

/**
 * Steps for hashing a password:
 * 1. Create a salt
 * 2. Use that salt along with the password to create a hashed password
 */
