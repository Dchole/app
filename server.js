const express = require("express")
const mongoose = require("mongoose")
const path = require("path")

const app = express()
const PORT = process.env.PORT || 5000

require("dotenv").config()

const tasks = require("./routes/api/tasks")

// Middlewares
app.use(express.json())

mongoose
  .connect(process.env.DB, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useCreateIndex: true,
    useFindAndModify: false
  })
  .then(() => console.log("Connected to Database!"))
  .catch(err => console.log(err))

// Routes Middlewares
app.use("/api/tasks", tasks)
app.use(express.static(path.join(__dirname, "build")))

app.get("*", (req, res) =>
  res.sendFile(path.join(__dirname, "build", "index.html"))
)

app.listen(PORT, () => console.log(`App running on port ${PORT}`))
