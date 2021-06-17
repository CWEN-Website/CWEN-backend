// create an express app
const express = require("express")
const app = express()
//const data = require("./Login.json");
var data;

// setting the information for SQL
try{
  data = require("./Login.json");
}catch{
  data = {
    host: process.env.SQL_HOST,
    user: process.env.SQL_USER,
    password: process.env.SQL_Pass,
    database: process.env.SQL_DATABASE,
  }
}


var mysql = require('mysql');
var pool  = mysql.createPool({
  connectionLimit : 10,
  host            : '',
  user            : 'cwenweb_sql',
  password        : 'secret',
  database        : 'cwenweb_CWENWEB'
});

// use the express-static middleware
app.use(express.static("public"))

// define the first route
app.get("/", function (req, res) {
  res.send("<h1>Change</h1>")
})

app.get("/login", function(req,res) {
  console.log(data);
  res.send("Login Page");
})

// start the server listening for requests
app.listen(process.env.PORT || 4000, 
	() => console.log("Server is running..."));