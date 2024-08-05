const passport = require('passport');

exports.isAuth = (req, res, next) => {
  return passport.authenticate('jwt')
};

exports.sanitizeUser = (user)=>{
    return {id:user.id, role:user.role}
};


exports.cookieExtractor = function(req){
    var token = null;
    if(req && req.cookies)
    {
        token = req.cookies['jwt'];
    }
//     //admin
//    token='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY2YWZlNDkwMTczM2U2NTExYTIyM2QzNCIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTcyMjgwMzM0NH0.rqnt4GtjZXkiKlA-Ypy3cN3sLpi5oxmd6o28XMesTDY' 
    

//user demo
   token= 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6IjY2YWY4ZjRmNjZjNjM1MzQwOTQzYzI5OCIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNzIyNzgxNTE5fQ.pMpQem2o_RJpf7aWsRnLSQVSyvv6LlBOaCr_EICJht0'
    return token;
};