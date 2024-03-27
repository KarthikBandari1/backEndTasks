const express = require('express')
const bodyParser = require('body-parser')
const cors = require('cors')
const {open} = require('sqlite')
const sqlite3 = require('sqlite3')
const path = require('path')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const axios = require('axios')
const swaggerUI = require('swagger-ui-express')
const YAML = require('yamljs')
const swaggerJSDocs = YAML.load('./api.yaml')

const databasePath = path.join(__dirname, 'user.db')

const app = express()
app.use(cors())
app.use(bodyParser.json())
app.use(express.json())

app.use('/api-docs', swaggerUI.serve, swaggerUI.setup(swaggerJSDocs))

let database = null
const initializeDbAndServer = async () => {
  try {
    database = await open({
      filename: databasePath,
      driver: sqlite3.Database,
    })
    app.listen(3002, () =>
      console.log('Server Running at http://localhost:3002/'),
    )
  } catch (error) {
    console.log(`DB Error: ${error.message}`)
    process.exit(1)
  }
}
initializeDbAndServer()

// Task 1
app.post('/register', async (request, response) => {
  const {username, email, password} = request.body
  const hashedPassword = await bcrypt.hash(password, 10)
  const selectUserQuery = `SELECT * FROM userDetails WHERE Name = '${username}'`
  const dbUser = await database.get(selectUserQuery)
  if (dbUser === undefined) {
    const createUserQuery = `
      INSERT INTO
        userDetails (Name, Email, password)
      VALUES
        (
          '${username}',
          '${email}',
          '${hashedPassword}'
        )`

    const dbResponse = await database.run(createUserQuery)

    const newUserId = dbResponse.lastID
    response.send(`Created new user with User ID ${newUserId}`)
  } else {
    response.status(400).send('User already exists')
  }
})

app.post('/login', async (request, response) => {
  const {username, password} = request.body
  const selectUserQuery = `SELECT * FROM userDetails WHERE Name = '${username}'`
  const dbUser = await database.get(selectUserQuery)
  if (dbUser === undefined) {
    response.status(400)
    response.send('Invalid User')
  } else {
    const isPasswordMatched = await bcrypt.compare(password, dbUser.password)
    if (isPasswordMatched === true) {
      const payload = {
        Name: username,
      }
      const jwtToken = jwt.sign(payload, 'MY_SECRET_TOKEN')
      response.send({jwtToken})
    } else {
      response.status(400)
      response.send('Invalid Password')
    }
  }
})

//function to check whether the jwt token in valid token or invalid token. It returns true if it is invalid token
const is_not_valid_token = async jwt => {
  try {
    const token_query = 'SELECT * FROM invalidated_tokens WHERE token = ?'
    const tokenRow = await database.all(token_query, [jwt])
    if (tokenRow.length > 0) {
      return true
    } else {
      return false
    }
  } catch (error) {
    console.error('Error occurred while checking token validity:', error)
    return true
  }
}

//Middleware function to authenticate the user. by validating the jwt token.
//Validating jwt token involves verifying the token or checking that it in invalidated_tokens table.
const authenticateToken = async (request, response, next) => {
  let jwtToken
  const authHeader = request.headers['authorization']
  if (authHeader !== undefined) {
    jwtToken = authHeader.split(' ')[1]
  }
  if (jwtToken === undefined || (await is_not_valid_token(jwtToken))) {
    response.status(401)
    response.send('Invalid JWT Token, it has been destroyed or undefined')
  } else {
    jwt.verify(jwtToken, 'MY_SECRET_TOKEN', async (error, payload) => {
      if (error) {
        response.status(401)
        response.send('Invalid JWT Token')
      } else {
        request.username = payload.Name
        next()
      }
    })
  }
}

//when this logout api is called, the jwt token will be destroyed (inserted into the database invalidated_tokens table)
app.get('/logout', async (request, response) => {
  let jwtToken
  const authHeader = request.headers['authorization']
  if (authHeader !== undefined) {
    jwtToken = authHeader.split(' ')[1]
  }
  if (jwtToken === undefined) {
    response.status(401).send('Invalid JWT Token')
  } else {
    try {
      await database.run(
        `INSERT INTO invalidated_tokens (token) VALUES ('${jwtToken}');`,
      )
      response.send('User has been Logged Out')
    } catch (error) {
      console.error('Error logging out user:', error)
      response.status(500).send('Internal Server Error')
    }
  }
})

//Task 2
async function fetchData() {
  try {
    const response = await axios.get('https://api.publicapis.org/entries')
    return response.data.entries
  } catch (error) {
    console.error('Error fetching data:', error)
    return []
  }
}

app.get('/api/data', async (req, res) => {
  const {category, limit, offset, https, cors, auth} = req.query
  try {
    let data = await fetchData()
    if (category) {
      data = data.filter(
        entry => entry.Category.toLowerCase() === category.toLowerCase(),
      )
    }
    if (offset) {
      data = data.slice(parseInt(offset))
    }
    if (limit) {
      data = data.slice(0, parseInt(limit))
    }

    if (https) {
      data = data.filter(
        entry => entry.HTTPS.toString().toLowerCase() === https.toLowerCase(),
      )
    }

    if (cors) {
      data = data.filter(
        entry => entry.Cors.toLowerCase() === cors.toLowerCase(),
      )
    }
    if (auth) {
      data = data.filter(
        entry => entry.Auth.toLowerCase() === auth.toLowerCase(),
      )
    }
    res.json(data)
  } catch (error) {
    console.error('Error processing request:', error)
    res.status(500).json({error: 'Internal server error'})
  }
})

//Task 4
app.get('/user', authenticateToken, async (request, response) => {
  console.log('hi')
  const getUsersQuery = `
   SELECT
    *
   FROM
    userDetails
   where Name='${request.username}';`
  const userDetails = await database.get(getUsersQuery)
  response.send(userDetails)
})
