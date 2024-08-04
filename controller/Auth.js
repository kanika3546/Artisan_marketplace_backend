const { User } = require('../model/User');

const crypto = require('crypto');
const { sanitizeUser } = require('../services/common');
const SECRET_KEY = 'SECRET_KEY';
const jwt = require('jsonwebtoken');


exports.createUser = async (req, res) => {
  try {
    const salt = crypto.randomBytes(16);
    crypto.pbkdf2(req.body.password, salt, 310000, 32, 'sha256', async (err, hashedPassword) => {
      if (err) {
        return res.status(500).json({ error: 'Internal Server Error' });
      }
      try {
        const user = new User({ ...req.body, password: hashedPassword, salt });
        const doc = await user.save();

        req.login(sanitizeUser(doc), (err) => {
          if (err) {
            res.status(400).json(err);
          } else {
            const token = jwt.sign(sanitizeUser(doc), SECRET_KEY);
            res.status(201).json(token);
          }
        });
      } catch (saveErr) {
        res.status(400).json({ error: saveErr.message });
      }
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
};

//         req.login(sanitizeUser(doc), (err) => {  // this also calls serializer and adds to session
//           if (err) {
//             res.status(400).json(err);
//           } else {
//             const token = jwt.sign(sanitizeUser(doc), SECRET_KEY);
//             res.status(201).json(token);
//           }
//         });
//       }
//     );
//   } catch (err) {
//     res.status(400).json(err);
//   }
// };


exports.loginUser = async (req, res) => {
 //res.json({status:'success'});
 console.log('User:', req.user);
 
 res.json(req.user);
 };

exports.checkUser =  (req, res) => {
  res.json({status:'success',user: req.user})};
