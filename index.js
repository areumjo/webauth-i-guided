const express = require('express');
const helmet = require('helmet');
const cors = require('cors');

// npm install bcryptjs
const bcrypt = require('bcryptjs');

const db = require('./database/dbConfig.js');
const Users = require('./users/users-model.js');

const server = express();

server.use(helmet());
server.use(express.json());
server.use(cors());

server.get('/', (req, res) => {
  res.send("It's alive!");
});

server.post('/api/register', (req, res) => {
  let user = req.body;
  console.log('password arrivign from client ', user.password);

  // we like to have `slow` hashing fn ==> running this fn two to 10 (1024) times!
  user.password = bcrypt.hashSync(user.password, 10);
  console.log('password heading to db', user.password);

  Users.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

server.post('/api/login', (req, res) => {
  let { username, password } = req.body;

  // password = bcrypt.hashSync(password, 10); ==> this will throw error, bc when user types right pw, this will hash again and not match to db-stored one

  Users.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        res.status(200).json({ message: `Welcome ${user.username}!` });
      } else {
        res.status(401).json({ message: 'Invalid Credentials' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

// protect this info -- authentication
// req.headers should have a correct username/password ==> req.header.username, req.headers.password
// if they are not correct, we should be blocked
server.get('/api/users', restricted, (req, res) => {
  Users.find()
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

// middleware
function restricted(req, res, next) {
  // the password does NOT belong in the headers
  const { username, password } = req.headers;

  if (username && password) {
    Users.findBy({ username })
      .first()
      .then(user => {
        if (user && bcrypt.compareSync(password, user.password)) {
          next();
        } else {
          res.status(401).json({ message: "Invalid credentials" });
        }
      })
      .catch(err => {
        res.status(500).json({ message: "unexected error" })
      })
  } else {
    res.status(400).json({ message: "please provide username and password"});
  }
}

const port = process.env.PORT || 5000;
server.listen(port, () => console.log(`\n** Running on port ${port} **\n`));
