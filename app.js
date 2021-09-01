var aes256 = require('aes256');
const express = require("express");
const app = express();
try{
const dotenv = require('dotenv');
dotenv.config();
}catch(e){}
var data;
const salt = require('node-forge');
const pass = require('node-forge');
const nodemailer = require('nodemailer');
const emailAddress = "website.cwen@gmail.com";
var multer  = require('multer');
var upload = multer({ dest: 'uploads/' })
const { google } = require("googleapis");
const OAuth2 = google.auth.OAuth2;

// sets signedURL expired time
const signedUrlExpireSeconds = 60 * 60;

const fs = require('fs');
const S3 = require('aws-sdk/clients/s3');
var aes256 = require('aes256');
const cors = require('cors');

app.use(cors());
var bucketName, region, accessKeyId, secretAccessKey
//lalala

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

// OAUTH Configurations
const oauth2Client = new OAuth2(
  process.env.GMAIL_OAUTH_CLIENT_ID,
  process.env.GMAIL_OAUTH_CLIENT_SECRET,
  "https://developers.google.com/oauthplayground"
);

oauth2Client.setCredentials({
  refresh_token: process.env.GMAIL_OAUTH_REFRESH_TOKEN
});

const createTransporter = async () => {
  const oauth2Client = new OAuth2(
    process.env.GMAIL_OAUTH_CLIENT_ID,
    process.env.GMAIL_OAUTH_CLIENT_SECRET,
    "https://developers.google.com/oauthplayground"
  );

  oauth2Client.setCredentials({
    refresh_token: process.env.GMAIL_OAUTH_REFRESH_TOKEN
  });
};

const accessToken = new Promise((resolve, reject) => {
  oauth2Client.getAccessToken((err, token) => {
    if (err) {
      reject("Failed to create access token :(");
    }
    resolve(token);
  });
});


// email

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    type: "OAuth2",
    user: emailAddress,
    accessToken,
    clientId: process.env.GMAIL_OAUTH_CLIENT_ID,
    clientSecret: process.env.GMAIL_OAUTH_CLIENT_SECRET,
    refreshToken: process.env.GMAIL_OAUTH_REFRESH_TOKEN
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

// basic info found in sql databases
app.get("/eOfMonthInfo", function(req, res){
  let eOfMonthQuery = "SELECT * FROM eOfMonth;"

  pool.query(eOfMonthQuery, (err, data) =>{
    if(err){
      console.log(queryToken);
      console.log(err);
      return res.end("err");
    }else{
      
      let monthData = {
        name: data[0].eName,
        company: data[0].company,
        picURL: getURL("Woman Entreprenuer of the Month.jpg"),
      }

    
      res.json(monthData);
    }
  })
})

app.get("/eOfMonthBlurb", function(req, res){
  getS3Text("EofMonthBlurb.txt").then(content => res.send(content))  
})

app.get("/eOfMonthProducts", function(req, res){
  let eOfMonthProductsQuery = "SELECT products FROM eOfMonth";

  pool.query(eOfMonthProductsQuery, (err, data) => {
    if(err){
      res.send(err);
    }else{
      let dummyArray = []

      for(let i = 0; i < data[0].products; i++){
        dummyArray[i] = i + 1;
      }

      let productData = {
        products: dummyArray.map((num) => getURL("Month product " + num + ".jpg"))
      }

      res.json(productData);
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

  if(token === "null"){
    res.end("unfound");
  }

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
          title: "author",
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

})//Fathila Nanozi, Head of Programs, https://cwen-storage.s3.us-east-2.amazonaws.com/Fathila+Nanozi.jpg, 2



app.post('/updateMonth', upload.array('photos', 12), function (req, res, next) {
  // req.files is an object (String -> Array) where fieldname is the key, and the value is array of files
  //
  // e.g.
  //  req.files.pic[0] -> File
  //  req.files.products -> Array
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
      }else if(!results[0].isAdmin){ // is author
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

// http://localhost:4000/join?name=Test+Name&email=testcwenaaa@gmail.com&phoneNum=256123456789&buisness=test+LLP&description=A+Test+for+stuff&region=Northern&district=Buikew&town=Buikew
app.get("/join", function(req, res){
  const {name, email, phoneNum, buisness, description, region, district, town} = req.query;

  let joinQuery = "INSERT INTO members VALUES(?,?,?,?,?,?,?,?)"
  let inserts = [];

  inserts[0] = name;
  inserts[1] = email;
  inserts[2] = phoneNum;
  inserts[3] = buisness;
  inserts[4] = "https://cwen-storage.s3.us-east-2.amazonaws.com/descripton+of+" + email +"'s+buisness.txt";
  inserts[5] = region;
  inserts[6] = district;
  inserts[7] = town;

  joinQuery = mysql.format(joinQuery, inserts);

  pool.query(joinQuery, (err, results) => {
    if(err){
      if(err.code === "ER_DUP_ENTRY"){
        res.send("duplicate");
      }else{
        console.log(joinQuery);
        console.log(err);
        return res.end("err");
      }


    }else{
        // create txt filestream.
      let buf = Buffer.from(description);
      uploadS3Text(buf, "descripton of " + email +"'s buisness.txt", true)
      .then(res.send("Succes!"));
    
    }})
})

// get all members
app.get("/getMembers", function(req, res){
  let getMembersQuery = "SELECT * FROM members";

  pool.query(getMembersQuery, (err, results) => {
    if (err){
      console.log(getMembersQuery);
        console.log(err.errno);
        return res.end("err");
    } else{
        res.json(results);
      }
    })
})

// http://localhost:4000/recieve_contact?name=Roy+He&email=royhe62@yahoo.ca&subject=How+can+I+join&message=Hello+This+Is+A+Test.
app.get("/recieve_contact", function(req, res){
  const{name, email, subject, message} = req.query;

  let dateSent = new Date();

  let messageQuery = "INSERT INTO contactUs VALUES(?,?,?,?,?)";

  let inserts = [];
  inserts[0] = dateSent;
  inserts[1] = name;
  inserts[2] = email;
  inserts[3] = subject;
  inserts[4] = email + "@" + dateSent + ".txt";
  console.log(inserts[3]);
  
  messageQuery = mysql.format(messageQuery,inserts);

  let htmlMessage = "<p>Recieved the following message from " + name + " (email:" + email + ") at " + dateSent + ":</p> <p>" + message.replace(/[\n\r]/g, '</p><p>') + "</p>";
  console.log(htmlMessage);

  var mailOptions = {
    from: emailAddress,
    to: "info@cwen.or.ug",
    subject: 'Contact Recieved',
    html: htmlMessage
  };

  pool.query(messageQuery, (err, results) => {
    if (err){
      console.log(messageQuery);
        console.log(err);
        return res.end("err");
    } else{
      transporter.sendMail(mailOptions, function(error, info){
        if (error) {
          console.log(error);
          res.end("email error");
        } else {
          console.log('Email sent: ' + info.response);
          
          let buf = Buffer.from(message);
          uploadS3Text(buf, email + "@" + dateSent + ".txt", false)
          .then(res.send("Succes!"));
        }
      });
      
    }
  })
})

app.get("/get_contact", function(req, res){
  const{offset} = req.query;

  let offsetNum = parseInt(offset);
  let contactQuery = "SELECT * FROM contactUs ORDER BY sent LIMIT 10 OFFSET ?"
  let inserts = [];
  inserts[0]= offsetNum;

  contactQuery = mysql.format(contactQuery, inserts);

  pool.query(contactQuery, (err, results) => {
    if (err){
      console.log(messageQuery);
        console.log(err);
        return res.end("err");
    } else{
      let downloadParams = {
        Key: results[0].messageKey,
        Bucket: bucketName
      }
      /*
      s3.getObject(downloadParams, (err, data) => {
        if(err){
          console.log(err);
          res.send(err);
        }

        res.send(data.Body.toString('ascii'))
      })*/


      let promises = results.map(content => getS3Text(content.messageKey));
      let finalPromise = Promise.all(promises).then((content) => {
        for(let i = 0; i < content.length; i++){
          results[i].message = content[i];
        }

        res.json(results);
      });
    }})
})

const blogUpload = upload.fields([{ name: 'data', maxCount: 1 }, { name: 'mainPhoto', maxCount: 1 }, { name: 'photos', maxCount: 100 }])
app.post("/newBlog", blogUpload, function(req, res){
  const{token, title, numPhotos} = req.query;
  let author = "";
  let id = 0;
  let dateUpdated = new Date();
  
  let blogQuery = "INSERT INTO blogs VALUES(?,?,?,false,?,?)";
  let idQuery = "SELECT idNum FROM blogs WHERE author = ? ORDER BY idNum DESC LIMIT 1;";

  let tokenQuery = "SELECT username FROM login WHERE passHash = ?"

  let inserts = [];

  // decrypt the token to get the salted hash
  inserts[0] = aes256.decrypt(data.privateKey, token);

  tokenQuery = mysql.format(tokenQuery, inserts);

  pool.query(tokenQuery, (err, results) => {
    if(err){
      console.log(tokenQuery);
      console.log(err);
      return res.end("err");
    }

    if(results.length === 0){
      res.send("unfound");
    }

    author = results[0].username;

    inserts[0] = author;

    idQuery = mysql.format(idQuery, inserts);
    // generating an ID
    pool.query(idQuery, (idErr, idRes) => {
      if(idErr){
        console.log(idQuery);
        console.log(idErr);
        return res.send("err");
      }

      console.log(idRes);
      if(idRes.length === 0){
        id = 1;
      }else{
        id = idRes[0].idNum + 1;
      }

      inserts[0] = author;
      inserts[1] = id;
      inserts[2] = title;
      inserts[3] = dateUpdated;
      inserts[4] = parseInt(numPhotos);

      blogQuery = mysql.format(blogQuery, inserts);

      // upload contentState
      uploadS3Text(req.body.data, author + "'s "  +  id + ".json");

      
      // upload mainImage

      uploadS3File(req.files.mainPhoto[0], author + "'s "  + id + "mainpic.jpg");

      // upload photos
      if(req.files.photos !== undefined){
        for(let i = 0; i < req.files.photos.length; i++){
          uploadS3File(req.files.photos[i], author + "'s "  + id + "pic" + i)
        }
      }

      pool.query(blogQuery, function(bErr, bRes){
        if(bErr){
          console.log(blogQuery);
          console.log(bErr);
          res.send("Error");
        }
        
        res.send("Done!");
      })
    })
  })
})

app.get("/getBlogContent", function(req, res){
  const{author,id} = req.query;

  let blogQuery = "SELECT * FROM blogs WHERE (author = ? AND idNum = ? AND isPublished = 1)"


  let inserts = []
  inserts[0] = author;
  inserts[1] = parseInt(id);
  let title = ""

  blogQuery = mysql.format(blogQuery, inserts)

  pool.query(blogQuery, (err, results) => {
    if(err){
      console.log(blogQuery);
      console.log(err);
      res.send(err);
    }

    if(results.length === 0){
      res.send("unfound");
    }else{
      title = results[0].title

      let awsKey = author + "'s "  + id + ".json";

      getS3Text(awsKey).then((json) => JSON.parse(json))
        .then((content) => {
          content.sqlStuff = results[0];
          res.json(content)
        });
    }
  })
})

app.get("/getBlogMainPhoto", function(req, res){
  const{author,id} = req.query;

  let blogQuery = "SELECT * FROM blogs WHERE (author = ? AND idNum = ? AND isPublished = 1)"


  let inserts = []
  inserts[0] = author;
  inserts[1] = parseInt(id);
  let title = ""

  blogQuery = mysql.format(blogQuery, inserts)

  pool.query(blogQuery, (err, results) => {
    if(err){
      console.log(blogQuery);
      console.log(err);
      res.send(err);
    }

    if(results.length === 0){
      res.send("unfound");
    }else{
      title = results[0].title

      let awsKey = author + "'s "  + id + "mainpic.jpg";

      let url = getURL(awsKey)
      
      res.send(url);
    }
  })
})

app.get("/getBlogPhotos", function(req, res){
  const{author,id} = req.query;

  let blogQuery = "SELECT * FROM blogs WHERE (author = ? AND idNum = ? AND isPublished = 1)"


  let inserts = []
  inserts[0] = author;
  inserts[1] = parseInt(id);
  let title = ""

  blogQuery = mysql.format(blogQuery, inserts)

  pool.query(blogQuery, (err, results) => {
    if(err){
      console.log(blogQuery);
      console.log(err);
      res.send(err);
    }


    if(results.length === 0){
      res.send("unfound");
    }else{
      let numberArray = [];
      let numPhotos = results[0].numPhotos;
      title = results[0].title
      

      for(let i = 0; i < numPhotos; i++){
        numberArray[i] = i;
      }

      let urlArrays = numberArray.map((element) => getURL(author + "'s "  + id + "pic" + element))

      res.json(urlArrays);
    }
  })
})

app.get("/getUnpublishedBlogContent", function(req, res){ 
  const{token,id} = req.query;

  let blogQuery = "SELECT * FROM blogs WHERE (author = ? AND idNum = ?)";

  let tokenQuery = "SELECT username FROM login WHERE passHash = ?"

  let inserts = [];

  // decrypt the token to get the salted hash
  inserts[0] = aes256.decrypt(data.privateKey, token);

  tokenQuery = mysql.format(tokenQuery, inserts);

  pool.query(tokenQuery, (err, results) => {
    if(err){
      console.log(tokenQuery);
      console.log(err);
      return res.end("err");
    }

    if(results.length === 0){
      res.send("unfound");
    }

    author = results[0].username;
    inserts[0] = author;
    inserts[1] = parseInt(id);

    blogQuery = mysql.format(blogQuery, inserts)
    pool.query(blogQuery, (err, results) => {
      if(err){
        console.log(blogQuery);
        console.log(err);
        res.send(err);
      }

      if(results.length === 0){
        res.send("unfound");
      }else{
        title = results[0].title

        let awsKey = author + "'s "  + id + ".json";

        getS3Text(awsKey).then((json) => JSON.parse(json))
          .then((content) => {
            content.sqlStuff = results[0];
            res.json(content)
          })
      }
    })
  })
  
})

app.get("/getUnpublishedBlogMainPhoto", function(req, res){ 
  const{token,id} = req.query;

  let blogQuery = "SELECT * FROM blogs WHERE (author = ? AND idNum = ?)";

  let tokenQuery = "SELECT username FROM login WHERE passHash = ?"

  let inserts = [];

  // decrypt the token to get the salted hash
  inserts[0] = aes256.decrypt(data.privateKey, token);

  tokenQuery = mysql.format(tokenQuery, inserts);

  pool.query(tokenQuery, (err, results) => {
    if(err){
      console.log(tokenQuery);
      console.log(err);
      return res.end("err");
    }

    if(results.length === 0){
      res.send("unfound");
    }

    author = results[0].username;
    inserts[0] = author;
    inserts[1] = parseInt(id);

    blogQuery = mysql.format(blogQuery, inserts)
    pool.query(blogQuery, (err, results) => {
      if(err){
        console.log(blogQuery);
        console.log(err);
        res.send(err);
      }
  
      if(results.length === 0){
        res.send("unfound");
      }else{
        title = results[0].title
  
        let awsKey = author + "'s "  + id + "mainpic.jpg";
  
        let url = getURL(awsKey)
        
        res.send(url);
      }
    })
  })
  
})


app.get("/getUnpublishedBlogPhotos", function(req, res){ 
  const{token,id} = req.query;

  let blogQuery = "SELECT * FROM blogs WHERE (author = ? AND idNum = ?)";

  let tokenQuery = "SELECT username FROM login WHERE passHash = ?"

  let inserts = [];

  // decrypt the token to get the salted hash
  inserts[0] = aes256.decrypt(data.privateKey, token);

  tokenQuery = mysql.format(tokenQuery, inserts);

  pool.query(tokenQuery, (err, results) => {
    if(err){
      console.log(blogQuery);
      console.log(err);
      res.send(err);
    }

    author = results[0].username;
    inserts[0] = author;
    inserts[1] = parseInt(id);

    blogQuery = mysql.format(blogQuery, inserts)
    pool.query(blogQuery, (err, results) => {
      if(err){
        console.log(blogQuery);
        console.log(err);
        res.send(err);
      }
  
  
      if(results.length === 0){
        res.send("unfound");
      }else{
        let numberArray = [];
        let numPhotos = results[0].numPhotos;
        title = results[0].title
        
  
        for(let i = 0; i < numPhotos; i++){
          numberArray[i] = i;
        }
        
  
        let urlArrays = numberArray.map((element) => getURL(author + "'s "  + id + "pic" + element))
  
        res.json(urlArrays);
      }
    })
  })
  
})

const blogUpdate = upload.fields([{ name: 'data', maxCount: 1 }, { name: 'mainPhoto', maxCount: 1 }, { name: 'photos', maxCount: 100 }])
// body is the contentstate
// mainPhoto is the main blog photo
// photos is the photos in the blog
app.post("/updateBlog", blogUpdate, function(req, res){
  const{token, id, title} = req.query;

  let tokenQuery = "SELECT username FROM login WHERE passHash = ?"

  let inserts = [];

  // decrypt the token to get the salted hash
  inserts[0] = aes256.decrypt(data.privateKey, token);

  tokenQuery = mysql.format(tokenQuery, inserts);

  pool.query(tokenQuery, (err, results) => {
    if(err){
      console.log(tokenQuery);
      console.log(err);
      return res.end("err");
    }

    if(results.length === 0){
      res.send("unfound");
    }

    let author = results[0].username

    // upload contentState
    uploadS3Text(req.body.data, author + "'s " + id + ".json");

    // upload mainImage
    if(req.files.mainPhoto !== undefined){
      uploadS3File(req.files.mainPhoto[0], author + "'s " + id + "mainpic.jpg");
    }

    //TODO how to update images


    // copy all images gotten from aws
    //console.log(JSON.parse(req.body.data).entityMap);

    let map = JSON.parse(req.body.data).entityMap;
    let entityIndex = 0;
    let imageIndex = 0;

    // we have to start at the end, and move back to the front
    // setting the indexes properly
    while(map[entityIndex] !== undefined){
      if(map[entityIndex].type === "IMAGE"){
        imageIndex++;
      }
      entityIndex++;
    }
    entityIndex--;
    imageIndex--;
    let usedKeysSet = new Set();
    
    // we are now working on copying the things

    while(map[entityIndex] !== undefined){
      let entity = map[entityIndex];
            
      if(entity.originalIndex !== undefined){
        // this was stored in the aws s3 already. Move it to its new place
        // author + "'s "  + id + "pic" + i
        let oldKey = author + "'s "  + id + "pic" + entity.originalIndex
        let newKey = author + "'s "  + id + "pic" + imageIndex;
        usedKeysSet.add(imageIndex);
        //console.log(oldKey);
        //console.log(newKey);
        copyS3Object(oldKey, newKey);
      }

      //console.log(entity.originalIndex);
      if(entity.type === "IMAGE"){
        imageIndex--;
      }

      entityIndex--;
    }


    // just add the photos raw. The rest will figure it out
    imageIndex = 0;

    console.log(usedKeysSet);
    for(let i = 0; i < req.files.photos.length; i++){
      while(usedKeysSet.has(imageIndex)){
        imageIndex++;
      }

      uploadS3File(req.files.photos[i], author + "'s "  + id + "pic" + imageIndex);
    }

    // update title
    let updateQuery = "UPDATE blogs SET title = ? WHERE author = ? AND idNum = ?"
    inserts[0] = title;
    inserts[1] = author;
    inserts[2] = id;

    updateQuery = mysql.format(updateQuery,inserts);

    pool.query(updateQuery, (updateErr, updateResults) =>{
      if(updateErr){
        console.log(updateQuery);
        console.log(updateErr);
        res.send("err");
      }else{
        res.send("Done!");
      }
    })
  })
})

app.get("/copyTest", function(req,res){
  copyS3Object("royhe62's Various Things6pic1", "royhe62's 6pic1")
    .then((data) => res.send(data))
    .catch((err) => res.send(err));
})

function copyS3Object(sourceKey, destKey){
  let source = "/" + bucketName + "/" + sourceKey;

  if(sourceKey === destKey){
    return "same";
  }
  var params = {
    Bucket: bucketName,
    CopySource: source, 
    Key: destKey
   };
   return s3.copyObject(params).promise()
}

// returns a promise. Use .then((content) -> ... to access text)
function getS3Text(fileName){
  return new Promise((resolve, reject) => {
    s3.getObject({
      Bucket: bucketName,
        Key: fileName
    }, (err, data) => {
        if (err){
          resolve(err)
        } else { 
          resolve(data.Body.toString("ascii"))
        }
      })
    })
}



//deletes a file
function deleteFile(key){
  const params = {
    Bucket: bucketName,
    Key: key
  }

  s3.deleteObject(params).promise();
}




// uploads text
function uploadS3Text(buffer, fName,isPublic) {
  const uploadParams = {
    Bucket: bucketName,
    Body: buffer,
    Key: fName
  }

  if(isPublic){
    uploadParams.ACL = 'public-read'
  }

  return s3.upload(uploadParams).promise();
}


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

  s3.upload(uploadParams).promise();
}



// downloads a file
function getFilePromise(fileKey) {
  

  const downloadParams = {
    Key: fileKey,
    Bucket: bucketName
  }

  return s3.getObject(downloadParams).promise(); //.createReadStream()
}

function replaceAll(str){

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
