// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const {checkUsernameFree, checkUsernameExists, checkPasswordLength} = require('./auth-middleware');
const router = require('express').Router();
const User = require('../users/users-model');
const bcrypt = require('bcryptjs')
/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */
router.post('/register',checkUsernameFree, checkPasswordLength, async (req, res, next) => {
  try{
    const {username, password} = req.body;
    const newUser = {
      username,
      password: bcrypt.hashSync(password, 8)
    }
    const created = await User.add(newUser);
    res.status(200).json(created)
  }catch (err){
    next(err)
  }
})

/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */
router.post('/login', checkUsernameExists, async (req, res, next) => {
  try{
    const {username, password} = req.body;
    const [userFromDb] = await User.findBy({username})
    const verified = bcrypt.compareSync(password, userFromDb.password)
    if(!verified){
      res.status(401).json({
        message: "Invalid credentials"
      })
    }
    req.session.user = userFromDb
    res.status(200).json({message: `Welcome ${username}!`});
  }catch (err){
    next(err)
  }
})

/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */
router.get('/logout', async (req, res, next) => {
  try{
    if(req.session.user){
      res.session.destroy((err) => {
        if(err){
          res.status(200).json({
            "message": "no session"
          })
        }else{
          res.status(200).json({
            "message": "logged out"
          })
        }
      })
    }
  }catch (err){
    next(err)
  }
})
 
// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router