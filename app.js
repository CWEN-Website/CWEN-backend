var aes256 = require('aes256');
const express = require("express");
const app = express();
const dotenv = require('dotenv');
dotenv.config();
var data;
const salt = require('node-forge');
const pass = require('node-forge');

// sets signedURL expired time
const signedUrlExpireSeconds = 60 * 60;

const fs = require('fs');
const S3 = require('aws-sdk/clients/s3');
var aes256 = require('aes256');
const cors = require('cors');

app.use(cors());
var bucketName, region, accessKeyId, secretAccessKey


// setting the information for SQL and s3

data = {
  host: process.env.SQL_HOST,
  user: process.env.SQL_USER,
  password: process.env.SQL_Pass,
  database: process.env.SQL_DATABASE,
  privateKey: process.env.PRIVATE_KEY,
}

bucketName = process.env.AWS_BUCKET_NAME;
region = process.env.AWS_BUCKET_REGION;
accessKeyId = process.env.AWS_ACCESS_KEY;
secretAccessKey = process.env.AWS_SECRET_KEY;
encryptionKey = process.env.ENCRYPTION_KEY;

// sql connnection
var mysql = require('mysql');
var pool  = mysql.createPool({
  connectionLimit : 10,
  host            : data.host,
  user            : data.user,
  password        : data.password,
  database        : data.database
});

const s3 = new S3({
  region,
  accessKeyId,
  secretAccessKey
})

// use the express-static middleware
app.use(express.static("public"))

// define the first route
app.get("/", function (req, res) {
  res.send("<h1>Change</h1>")
})

// the login page that checks if account and password exist
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

// example: http://localhost:4000/project_image?projectName=royhe+is+me
// always use spaces
app.get("/project_image", function(req,res) {
  const{projectName} = req.query;
  const imageName = projectName + ".jpg";

  getFilePromise(imageName)
  .then((stream) => {
    stream.createReadStream().pipe(res);
  }).catch(() =>{
    res.send("404");
  })
})

// adds a new signup to the sql table
app.get("/customer_signup", function(req,res){

  var plaintext = 'my plaintext message';

  var encryptedPlainText = aes256.encrypt(encryptionKey, plaintext);
  var decryptedPlainText = aes256.decrypt(encryptionKey, encryptedPlainText);
  res.send(decryptedPlainText);
})


// example: http://localhost:4000/url?projectName=royhe+is+me
// always use spaces
// gets signed url of an s3 object
app.get("/url", function(req,res) {
  const{projectName} = req.query;
  const imageName = projectName + ".jpg";
  const url = getURL(imageName);

  res.send(url);
})

function getURL(fileName){

  const url = s3.getSignedUrl('getObject', {
    Bucket: bucketName,
    Key: fileName,
    Expires: signedUrlExpireSeconds
  })

  return url;
}

// gets a JSON of all the data needed
// example: http://localhost:4000/projectData?projectName=royhe+is+me

app.get("/projectData", function(req,res) {
  const{projectName} = req.query;
  // the key of the image in s3
  const imageName = projectName + ".jpg";
  //the key of the text file in s3
  const textName = projectName + ".txt";
  //gets image url


  let data = {
    "url": null,
    "text": null
  };

  data["url"] = getURL(imageName);

  // gets text of the project

  console.log(textName);
  getFilePromise(textName)
  .then((stream) => {
    // gets text of project
    data["text"] = stream.Body.toString("ascii");
    res.json(data);
   // res.send(url);
  }).catch((error) =>{
    console.log(error);
    res.send("404");
  })
})

//TODO add get name from SQL
app.get("/eOfMonth", function(req,res){
  let monthData = {
    name: "Sandra Elobu Ejang",
    company: "Western Silk Road Limited",
    picURL: getURL("Woman Entreprenuer of the Month.jpg")
  }

  res.json(monthData);
})



// gets url for a entrepreneur of the month product
// like: http://localhost:4000/eOfMonthProduct?productNum=1
app.get("/eOfMonthProduct", function(req,res){
  // number of product
  const{productNum} = req.query;

  let monthData = {
    name: "Martha Stewart",
    productURLs: ""
  }

  const params = {
    Bucket: bucketName,
    Key: "key"
  }
  
  let filename = "Month product " + productNum + ".jpg";
  params.Key = filename;
  console.log(monthData);
  
  
  s3.headObject(params, function (err, metadata) {  
    console.log
    if (err && err.code === 'NotFound') {  
      res.send("404");
    } else {  
      // file does exist
      monthData.productURLs = getURL(filename);
      res.send(getURL(filename));
    }
  });
})

// uploads a file

function uploadFile(file) {
  const fileStream = fs.createReadStream(file.path)

  const uploadParams = {
    Bucket: bucketName,
    Body: fileStream,
    Key: file.filename
  }

  return s3.upload(uploadParams).promise()
}

// downloads a file
function getFilePromise(fileKey) {
  const downloadParams = {
    Key: fileKey,
    Bucket: bucketName
  }

  return s3.getObject(downloadParams).promise(); //.createReadStream()
}

// checks if a file with a specificed key exists
function doesFileExist(key){
  const params = {
    Bucket: bucketName,
    Key: key
  }

  s3.headObject(params).promise(); // check errno with promise
  return true;
}

// start the server listening for requests
app.listen(process.env.PORT || 4000, 
	() => console.log("Server is running..."));