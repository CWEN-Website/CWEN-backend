// create an express app
var aes256 = require('aes256');
const express = require("express")
const app = express()
var data;
const salt = require('node-forge');
const pass = require('node-forge');

// setting the information for SQL
try{
  data = require("./Login.json");

}catch{
  data = {
    host: process.env.SQL_HOST,
    user: process.env.SQL_USER,
    password: process.env.SQL_Pass,
    database: process.env.SQL_DATABASE,
    privateKey: process.env.PRIVATE_KEY
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
  const{username, password} = req.query;
  let saltGenerator = salt.md.sha256.create();
  let passHashGenerator = pass.md.sha256.create();
  let saltedPassword;
  let passHash;
  let queryLogin = "SELECT * FROM login WHERE username = ?"
  let inserts = [];
  let storedHash;     //password hash in the database

  saltGenerator.update(username); //generate a salt from their username

  saltedPassword = password + saltGenerator.digest().toHex(); //add the salt onto the password.

  passHashGenerator.update(saltedPassword);

  passHash = passHashGenerator.digest().toHex();        //generate a hash of the salted password

  inserts[0] = username;

  queryLogin = mysql.format(queryLogin, inserts);


  pool.query(queryLogin, (err, result) => {
    if(err){
      console.log(queryLogin);
      console.log(err);
      return res.end("err");
    }else{
      //the username does not exist
      if(result.length === 0){
        res.end("unfound");
      }else{
        storedHash = result[0].passHash;
        let token = aes256.encrypt(password, data.privateKey);

        if(passHash === storedHash){  // password is correct
          if(result[0].admin === 1){
            res.end("admin," + token);
          }else{
            res.end("writer," + token);
          }
        }else{                  //password is incorrect
          res.end("incorrect");
        }
      }
    }
  })
})

// start the server listening for requests
app.listen(process.env.PORT || 4000, 
	() => console.log("Server is running..."));