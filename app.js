var aes256 = require('aes256');
const express = require("express");
const app = express();
const dotenv = require('dotenv');
dotenv.config();
var data;
const salt = require('node-forge');
const pass = require('node-forge');
const nodemailer = require('nodemailer');
const emailAddress = "website.cwen@gmail.com"
var multer  = require('multer')
var upload = multer({ dest: 'uploads/' })

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
  database        : data.database,
  multipleStatements: true
});


// email

var transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: emailAddress,
    pass: process.env.EMAIL_PASSWORD
  }
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

  saltedPassword = password + saltGenerator.digest().toHex() + "CWEN"; //add the salt onto the password.

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
        console.log(passHash);
        let token = aes256.encrypt(data.privateKey, passHash);

        if(passHash === storedHash){  // password is correct
          if(result[0].isAdmin === 1){
            res.end("admin," + token);
          }else{
            res.end("author," + token);
          }
        }else{                  //password is incorrect
          res.end("incorrect");
        }
      }
    }
  })
})



// adds a new signup to the sql table
app.get("/customer_signup", function(req,res){

  var plaintext = 'my plaintext message';

  var encryptedPlainText = aes256.encrypt(encryptionKey, plaintext);
  var decryptedPlainText = aes256.decrypt(encryptionKey, encryptedPlainText);
  res.send(decryptedPlainText);
})


// generates a token and emails it to the person who wants to reset their password
app.get("/reset_request", function(req,res){
  // email of person who wants to change password
  const{email} = req.query;

  // token gnerator of sha256
  const tokenGenerator = pass.md.sha256.create();
  
  // query for checking if email exists
  let queryEmail = "SELECT username FROM login WHERE email = ?"
  let inserts = [];
  inserts[0] = email;
  queryEmail = mysql.format(queryEmail, inserts);


  // query of inserting a token into the table
  let queryInsertion = "INSERT INTO resetPass VALUES(?,?) ON DUPLICATE KEY UPDATE token = ?"
  

  pool.query(queryEmail, (err, results) => {
    if(err){
      console.log(queryEmail);
      console.log(err);
      return res.end("err");
    }else{
      if(results.length !== 1){
        res.send("unfound");
      }else{
        let tokenSeed = new Date() + results[0].username;
        tokenGenerator.update(tokenSeed);
        let token =tokenGenerator.digest().toHex();

        // udating insertion query
        inserts[0] = results[0].username;
        inserts[1] = token;
        inserts[2] = token;
        queryInsertion = mysql.format(queryInsertion, inserts);

        pool.query(queryInsertion, (error) => {
          if(error){
            console.log(results[0]);
            console.log(queryInsertion);
            console.log(error);
            return res.end("err");
          }else{

            let htmlMessage = "<p>Reset your password <a rel=\"nofollow\" href=\"" + process.env.SITE_URL + "reset?token=" + token + "\">here</a></p>"
            + "<br><p>If the link doesn't work, please paste the following link in your URL </p>"
            + "<p>" + process.env.SITE_URL + "reset?token=" + token + "</p>";

            var mailOptions = {
              from: emailAddress,
              to: email,
              subject: 'Password Reset',
              html: htmlMessage
            };

            transporter.sendMail(mailOptions, function(error, info){
              if (error) {
                console.log(error);
                res.end("email error");
              } else {
                console.log('Email sent: ' + info.response);
                
              res.send("token and email");
              }
            });

          }
        })
      }
    }
  })
})


app.get("/new_password", function(req, res){
  const {newPass, token} = req.query;
  let saltGenerator = salt.md.sha256.create();
  let passHashGenerator = pass.md.sha256.create();

  // query for checking the token status
  let queryToken = "SELECT username FROM resetPass WHERE token = ?"
  let inserts = []
  inserts[0] = token;
  queryToken = mysql.format(queryToken, inserts);

  // query for updating passhash and deleting the reset entry
  let queryUpdate = "UPDATE login SET passHash = ? WHERE username = ?; DELETE FROM resetPass WHERE username = ?"

  pool.query(queryToken, (err, username) =>{
      if(err){
        console.log(queryToken);
        console.log(err);
        return res.end("err");
      }else{
        if(username.length === 0){
          res.send("reject");
        }else{
          saltGenerator.update(username[0].username.toString());

          saltedPassword = newPass + saltGenerator.digest().toHex() + "CWEN";

          passHashGenerator.update(saltedPassword);

          inserts[0] = passHashGenerator.digest().toHex();
          inserts[1] = username[0].username.toString();
          inserts[2] = username[0].username.toString();

          queryUpdate = mysql.format(queryUpdate, inserts);

          pool.query(queryUpdate, (error) => {
            if(error){
              console.log(queryUpdate);
              console.log(error);
              return res.end("err");
            }else{
              console.log(queryUpdate)
              res.send("success");
            }
          })
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
  let eOfMonthQuery = "SELECT * FROM eOfMonth;"

  pool.query(eOfMonthQuery, (err, data) =>{
    if(err){
      console.log(queryToken);
      console.log(err);
      return res.end("err");
    }else{
      let dummyArray = []
      for(let i = 0; i < data[0].products; i++){
        dummyArray[i] = i + 1;
      }
      
      
      let monthData = {
        name: data[0].eName,
        company: data[0].company,
        picURL: getURL("Woman Entreprenuer of the Month.jpg"),
        products: dummyArray.map((num) => getURL("Month product " + num + ".jpg"))
      }

    
      res.json(monthData);
    }
  })

  
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


app.get("/check_token", function(req, res){
  const {token} = req.query;
  let queryToken = "SELECT username, isAdmin FROM login WHERE passHash = ?"

  console.log(token);

  let inserts = [];

  // decrypt the token to get the salted hash
  inserts[0] = aes256.decrypt(data.privateKey, token);

  console.log(inserts[0])
  

  queryToken = mysql.format(queryToken, inserts);


  
  pool.query(queryToken, (err, results) => {
    if(err){
      console.log(queryToken);
      console.log(err);
      return res.end("err");
    }else{
      let user = {
        title: "",
        username: ""
      }


      if(results.length == 0){
        // does not exist
        res.end("unfound");
      }else if(results[0].isAdmin){
        // is admin
        user = {
          title: "admin",
          username: results[0].username
        }


        res.json(user)
      }else{
        user = {
          title: "writer",
          username: results[0].username
        }


        res.json(user)
      }
    }
  })
})


// function for changing the files for entrepreneur of the month
// https://stackoverflow.com/questions/47253661/uploading-multiple-files-with-fetch-and-formdata-apis 
// https://stackoverflow.com/questions/61237355/how-to-save-my-input-values-to-text-file-with-reactjs

// gets the SQL table for every team member
// https://stackoverflow.com/questions/14375895/aws-s3-node-js-sdk-uploaded-file-and-folder-permissions
app.get("/get_members", function(req, res){
  let queryMembers = "SELECT * FROM ourTeam ORDER BY id";

  pool.query(queryMembers, (err, results) =>{
    if(err){
      console.log(err);
      console.log(queryMembers);
      res.send("err");
    }else{
      res.json(results);
    }
  })

})


app.post('/updateMonth', upload.array('photos', 12), function (req, res, next) {
  // req.files is an object (String -> Array) where fieldname is the key, and the value is array of files
  //
  // e.g.
  //  req.files['pic'][0] -> File
  //  req.files['products'] -> Array
  //
  // req.body will contain the text fields, if there were any

  const{token, newName, newCompany} = req.query;
 


  let queryToken = "SELECT username, isAdmin FROM login WHERE passHash = ?"


  let inserts = [];

  // decrypt the token to get the salted hash
  inserts[0] = aes256.decrypt(data.privateKey, token);

  

  queryToken = mysql.format(queryToken, inserts);


  
  pool.query(queryToken, (err, results) => {
    if(err){
      console.log(queryToken);
      console.log(err);
      return res.end("err");
    }else{
      let user = {
        title: "",
        username: ""
      }
          
      if(results.length == 0){
        // does not exist
        res.end("illegal");
      }else if(!results[0].isAdmin){ // is writer
        res.end("illegal");
      }else{
        // is admin
        let monthQuery = "DELETE FROM eOfMonth; INSERT INTO eOfMonth VALUES(?,?,?)"
        
        
        let numProducts = req.files.length - 1;
        inserts[0] = newName;
        inserts[1] = newCompany;
        inserts[2] = numProducts;

        monthQuery = mysql.format(monthQuery, inserts);

        console.log("month query: " + monthQuery);

        // upload profile picture
        uploadS3File(req.files[0], "Woman Entreprenuer of the Month.jpg");

        // delete all previous products
        for(let i = 0; i < 100; i++){
          let key = "Month product " + i + ".jpg"
          deleteFile(key)
        }

        for(let i = 1; i <= numProducts; i++){
          let key = "Month product " + i + ".jpg"

          uploadS3File(req.files[i], key);
        }

        pool.query(monthQuery, (err, results) => {
          if(err){
            console.log(queryToken);
            console.log(err);
            return res.end("err");
          }else{
            res.send("done");
          }})
        
      }
    }
  })

})

//deletes a file
function deleteFile(key){
  const params = {
    Bucket: bucketName,
    Key: key
  }

  s3.deleteObject(params).promise();
}

// uploads a file

function uploadS3File(file, fName) {
  const fileStream = fs.createReadStream(file.path)

  const uploadParams = {
    Bucket: bucketName,
    Body: fileStream,
    ContentType: file.mimetype,
    Key: fName
  }

  s3.upload(uploadParams).promise();
}

// uploads a file that anyone can view
async function uploadPublicFile(file, fName) {
  const fileStream = fs.createReadStream(file.path)

  const uploadParams = {
    Bucket: bucketName,
    Body: fileStream,
    Key: fName,
    ACL: 'public-read'
  }


}


// downloads a file
function getFilePromise(fileKey) {
  

  const downloadParams = {
    Key: fileKey,
    Bucket: bucketName
  }

  return s3.getObject(downloadParams).promise(); //.createReadStream()
}

// upload a file
function uploadFile(file) {
  const fileStream = fs.createReadStream(file.path)

  const uploadParams = {
    Bucket: bucketName,
    Body: fileStream,
    Key: file.filename
  }

  return s3.upload(uploadParams).promise()
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
