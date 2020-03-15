const router = require("express").Router()
const User = require("../../models/user")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const authenticate = require("../middleware/auth")

require("dotenv").config()

router.get("/getUser", authenticate, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password")
    res.json(user)
  } catch (err) {
    res.send(err)
  }
})

router.post("/register", async (req, res) => {
  const salt = bcrypt.genSaltSync(10)
  const hashedPassword = bcrypt.hashSync(req.body.password, salt)

  const user = new User({
    username: req.body.username,
    email: req.body.email,
    password: hashedPassword
  })

  try {
    await user.save()
    res.json({ message: "Sign Up successfull!" })
  } catch (err) {
    res.send(err)
  }
})

router.post("/login", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email })
    const password = bcrypt.compareSync(req.body.password, user.password)

    if (!user) return res.json({ message: "Wrong Email", path: "email" })
    if (!password)
      return res.json({ message: "Wrong Password!", path: "password" })
    const accessToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "2m"
    })
    const refreshToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET)
    // refreshTokens.push(refreshToken)

    res.json({ accessToken, refreshToken })
  } catch (err) {
    res.send(err)
  }
})

module.exports = router
