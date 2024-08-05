const express = require('express');
const passport = require('passport');
const { User } = require('../model/User');

const crypto = require('crypto');
const { sanitizeUser } = require('../services/common');
const jwt = require('jsonwebtoken');

const SECRET_KEY = 'SECRET_KEY';

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
            return res.status(400).json(err);
          } else {
            const token = jwt.sign(sanitizeUser(doc), SECRET_KEY);
            res.cookie('jwt', token, {
              expires: new Date(Date.now() + 3600000),
              httpOnly: true,
            });
            return res.status(201).json({id:doc.id, role:doc.role});
          }
        });
      } catch (saveErr) {
        return res.status(400).json({ error: saveErr.message });
      }
    });
  } catch (err) {
    return res.status(400).json({ error: err.message });
  }
};






// exports.loginUser = async (req, res) => {
//   res.cookie('jwt', req.user.token, {
//     expires: new Date(Date.now() + 3600000),
//     httpOnly: true,
//   });
//   return res.status(201).json(req.user.token);
// };


exports.loginUser = async (req, res) => {
  const token = jwt.sign(sanitizeUser(req.user), SECRET_KEY);
  res.cookie('jwt', token, {
    expires: new Date(Date.now() + 3600000), // 1 hour
    httpOnly: true,
  });
  return res.status(201).json(req.user);
};

// exports.checkUser =  (req, res) => {
  // res.json({status:'success',user: req.user})};

exports.checkAuth = async (req, res) => {
  if(req.user){
    res.json(req.user);
  } else{
    res.sendStatus(401);
  }};
