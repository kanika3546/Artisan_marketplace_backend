
const express = require('express');
const server = express();
const mongoose = require('mongoose');
const cors = require('cors');
const axios = require("axios");
const bodyParser = require("body-parser");

const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const cookieParser = require('cookie-parser');
const path = require('path');

// const paymentServiceUrl = 'http://localhost:8000';

 require("dotenv").config();

const { createProduct } = require('./controller/Product');
const productsRouter = require('./routes/Products');
const categoriesRouter = require('./routes/Categories');
const brandsRouter = require('./routes/Brands');
const usersRouter = require('./routes/Users');
const authRouter = require('./routes/Auth');
const cartRouter = require('./routes/Cart');
const ordersRouter = require('./routes/Order');

const { User } = require('./model/User');
const { isAuth, sanitizeUser, cookieExtractor } = require('./services/common');
// const { clearCartForUser } = require('./controller/Cart');
const SECRET_KEY = 'SECRET_KEY';
// JWT options
const opts = {};
opts.jwtFromRequest = cookieExtractor;
// opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
opts.secretOrKey = SECRET_KEY; 

//middlewares
server.use(express.json());
server.use(express.raw({type: 'application/json'}));
server.use(express.static(path.join(__dirname, 'build')));

server.use(cookieParser());


server.use(
    session({
      secret: 'keyboard cat',
      resave: false, // don't save session if unmodified
      saveUninitialized: false, // don't create session until something stored
    })
  );
server.use(passport.authenticate('session'));
server.use(
  cors({   
     origin: 'http://localhost:3000', // Your frontend URL
    credentials: true, // Allow credentials
    exposedHeaders: ['X-Total-Count'],
  })
);
server.use(passport.initialize());
server.use(passport.session());


// server.use('/payment', (req, res) => {
//   // Forward the request to the payment service
//   const url = `${paymentServiceUrl}${req.url}`;
//   req.pipe(request(url)).pipe(res);
// });

server.use('/products', isAuth(), productsRouter.router);
server.use('/categories', isAuth(), categoriesRouter.router);
server.use('/brands', isAuth(), brandsRouter.router);
server.use('/users', isAuth(), usersRouter.router);
server.use('/auth', authRouter.router);
server.use('/cart', isAuth(), cartRouter.router);
server.use('/orders', isAuth(), ordersRouter.router);

passport.use('local', new LocalStrategy({
    usernameField: 'email',  // Specify the username field
    passwordField: 'password' // Specify the password field
  },
  async function (email, password, done) {
    try {
      const user = await User.findOne({ email: email }).exec();

      if (!user) {
        return done(null, false, { message: 'invalid credentials' });
      }
      crypto.pbkdf2(password, user.salt, 310000, 32, 'sha256', async function (err, hashedPassword) {
        if (!crypto.timingSafeEqual(user.password, hashedPassword)) {
          console.log('Error hashing password:', err);
          return done(null, false, { message: 'invalid credentials' });
      }
      const token = jwt.sign(sanitizeUser(user), SECRET_KEY);
      done(null, {id:user.id, role:user.role,token }) // this lines sends to serializer
    }
  );
    } catch (err) {
      return done(err);
    }
  }
));

passport.use('jwt', new JwtStrategy(opts, async function (jwt_payload, done) {
    console.log({ jwt_payload });
    try {
      const user = await User.findById(jwt_payload.id);;
      if (user) {
        return done(null, sanitizeUser(user)); // this calls serializer
      } else {
        return done(null, false);
      }
    } catch (err) {
      return done(err, false);
    }
  })
);




passport.serializeUser(function (user, cb) {
    console.log('serialize', user);
    process.nextTick(function () {
      return cb(null, { id: user.id, role: user.role });
    });
  });
  
  // this changes session variable req.user when called from authorized request
  
passport.deserializeUser(function (user, cb) {
  console.log('de-serialize', user);
  process.nextTick(function () {
    return cb(null, user);
  });
});



let salt_key = process.env.SALT_KEY
let merchant_id = process.env.MERCHANT_ID

// express.get("/", (req, res) => {
//     res.send("server is running");
// })

server.post("/orde", async (req, res) => {
    try {
        console.log(req.body)
        const merchantTransactionId = req.body.transactionId;
        const data = {
            merchantId: merchant_id,
            merchantTransactionId: merchantTransactionId,
            merchantUserId: req.body.MUID,
            name: req.body.name,
            amount: req.body.amount * 100,
            redirectUrl: `http://localhost:8080/status/?id=${merchantTransactionId}`,
            redirectMode: 'POST',
            mobileNumber: req.body.number,
            paymentInstrument: {
                type: 'PAY_PAGE'
            }
        };


        const payload = JSON.stringify(data);
        const payloadMain = Buffer.from(payload).toString('base64');
        const keyIndex = 1;
        const string = payloadMain + '/pg/v1/pay' + salt_key;
        const sha256 = crypto.createHash('sha256').update(string).digest('hex');
        const checksum = sha256 + '###' + keyIndex;

        // const prod_URL = "https://api.phonepe.com/apis/hermes/pg/v1/pay"
        const prod_URL = "https://api-preprod.phonepe.com/apis/pg-sandbox/pg/v1/pay"

        const options = {
            method: 'POST',
            url: prod_URL,
            headers: {
                accept: 'application/json',
                'Content-Type': 'application/json',
                'X-VERIFY': checksum
            },
            data: {
                request: payloadMain
            }
        };


        axios.request(options).then(function (response) {
                console.log(response.data)

                return res.json(response.data)
            })
            .catch(function (error) {
                console.error(error);
            });

    } catch (error) {
        res.status(500).send({
            message: error.message,
            success: false
        })
    }

})


server.post("/status", async (req, res) => {

    const merchantTransactionId = req.query.id;
    const merchantId = merchant_id

    const keyIndex = 1;
    const string = `/pg/v1/status/${merchantId}/${merchantTransactionId}` + salt_key;
    const sha256 = crypto.createHash('sha256').update(string).digest('hex');
    const checksum = sha256 + "###" + keyIndex;

    const options = {
        method: 'GET',
        url: `https://api-preprod.phonepe.com/apis/pg-sandbox/pg/v1/status/${merchantId}/${merchantTransactionId}`,
        headers: {
            accept: 'application/json',
            'Content-Type': 'application/json',
            'X-VERIFY': checksum,
            'X-MERCHANT-ID': `${merchantId}`
        }
    };

 

   // CHECK PAYMENT STATUS
    axios.request(options).then(async (response) => {
            if (response.data.success === true) {
              //  const url = `http://localhost:3000/success`
             // const url=  `http://localhost:3000/order-success/${currentOrder.id}`
            // Adjust this according to your auth setup

             // Clear the user's cart
         
             const url=  `http://localhost:3000/`  
         
           //  const url=  `http://localhost:8080/` 
             return res.redirect(url)
            } else {
                const url = `http://localhost:8080/`
                return res.redirect(url)
            }
        })
        .catch((error) => {
            console.error(error);
        });

})















main().catch((err) => console.log(err));

async function main() {
  await mongoose.connect('mongodb://127.0.0.1:27017/ecommerce');
  console.log('database connected');
}

// function isAuth() {
//     return function (req, res, next) {
//       if (req.user) {
//         next(); // Call next middleware
//       } else {
//         res.sendStatus(401); // Send 401 Unauthorized
//       }
//     };
//   }

server.listen(8080, () => {
  console.log('server started');
});

