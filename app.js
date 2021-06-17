// create an express app
const express = require("express")
const app = express()
//const data = require("./Login.json");
var data;

// setting the information for SQL
try{
  data = require("./Login.json");
  //const SQL_HOST = johnny.heliohost.org;
 // const SQL_USER =
}catch{
  data = {
    host: process.env.SQL_HOST,
    user: process.env.SQL_USER,
    password: process.env.SQL_Pass,
    database: process.env.SQL_DATABASE
  }
}


var mysql = require('mysql');
var pool  = mysql.createPool({
  connectionLimit : 10,
  host            : data.host,
  user            : data.user,
  password        : data.password,
  database        : data.database
});

// use the express-static middleware
app.use(express.static("public"))

// define the first route
app.get("/", function (req, res) {
  res.send("<h1>Change</h1>")
})

app.get("/login", function(req,res) {
 // console.log(data.host);
  res.send("Login");
})

// start the server listening for requests
app.listen(process.env.PORT || 4000, 
	() => console.log("Server is running..."));