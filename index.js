var express = require("express");
var cors = require("cors");
var app = express();
var bodyParser = require("body-parser");
var jsonParser = bodyParser.json();
const bcrypt = require("bcrypt");
const saltRounds = 10;
var jwt = require("jsonwebtoken");
const secret = "Fullstack-Login-2022";

app.use(cors());

const mysql = require("mysql2");
// create the connection to database
const connection = mysql.createConnection({
  host: "localhost",
  user: "root",
  database: "mydb",
});

const generatePassword = async (password) => {
  const salt = await bcrypt.genSalt(saltRounds);
  const passwordHash = await bcrypt.hash(password, salt);
  return passwordHash;
};

app.post("/register", jsonParser, async function (req, res, next) {
  const hashPassword = await generatePassword(req.body.password);
  console.log(hashPassword);
  connection.execute(
    "INSERT INTO users (email, password, fname, lname) VALUES (?, ?, ?, ?)",
    [req.body.email, hashPassword, req.body.fname, req.body.lname],
    function (err, results, fields) {
      if (err) {
        res.json({ status: "error", message: err });
        return;
      }
      res.json({ status: "ok" });
    }
  );
});

app.post("/login", jsonParser, function (req, res, next) {
  connection.execute(
    "SELECT * FROM users WHERE email=?",
    [req.body.email],
    function (err, users, fields) {
      if (err) {
        res.json({ status: "error", message: err });
        return;
      }
      if (users.length == 0) {
        res.json({ status: "error", message: "no user found" });
        return;
      }
      const password = req.body.password.trim();
      const existPassword = users[0].password.trim();
      bcrypt
        .compare(password, existPassword)
        .then((isLogin) => {
          if (isLogin) {
            var token = jwt.sign({ email: users[0].email }, secret, {
              expiresIn: "1h",
            });
            res.json({ status: "ok", message: "login success", token });
          } else {
            res.json({ status: "error", message: "login failed" });
          }
        })
        .catch((err) => {
          console.log(err);
        });
    }
  );
});

app.post("/authen", jsonParser, function (req, res, next) {
  try {
    const token = req.headers.authorization.split(" ")[1];
    var decoded = jwt.verify(token, secret);
    res.json({ status: "ok", decoded });
  } catch(err) {
    res.json({ status: "error", message: err.message });
  }
});

app.listen(3333, function () {
  console.log("CORS-enabled web server listening on port 3333");
});
