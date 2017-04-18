var crypto = require('crypto');
var mongoose = require('mongoose'),
    User = mongoose.model('User');
function hashPW(pwd){
  return crypto.createHash('sha256').update(pwd).
         digest('base64').toString();
}
exports.signup = function(req, res){
	User.findOne({ username: req.body.username })
  .exec(function(err, user) {
	  if(!user){
  console.log("Begin exports.signup");
  var user = new User({username:req.body.username});
  console.log("after new user exports.signup");
  user.set('hashed_password', hashPW(req.body.password));
  console.log("after hashing user exports.signup");
  user.set('level', 1);
  console.log("current level:"+user.level);
  user.save(function(err) {
    console.log("In exports.signup");
    console.log(err);
    if (err){
      res.session.error = err;
      res.redirect('/signup');
    } else {
      req.session.user = user.id;
      req.session.username = user.username;
      req.session.msg = 'Authenticated as ' + user.username;
	  req.session.level = user.level ;
      res.redirect('/');
    }
  });
	  }
	  else{
		  err = 'Sorry, username already taken.' ;
	  }
  });
};
exports.login = function(req, res){
  User.findOne({ username: req.body.username })
  .exec(function(err, user) {
    if (!user){
      err = 'User Not Found.';
    } else if (user.hashed_password === 
               hashPW(req.body.password.toString())) {
      req.session.regenerate(function(){
        console.log("a USER has just logged IN");
        console.log(user);
        req.session.user = user.id;
        req.session.username = user.username;
        req.session.msg = 'Authenticated as ' + user.username;
        req.session.level = user.level;
        res.redirect('/');
      });
    }else{
      err = 'Authentication failed.';
    }
    if(err){
      req.session.regenerate(function(){
        req.session.msg = err;
        res.redirect('/login');
      });
    }
  });
};
exports.getUserProfile = function(req, res) {
  User.findOne({ _id: req.session.user })
  .exec(function(err, user) {
    if (!user){
      res.json(404, {err: 'User Not Found.'});
    } else {
      res.json(user);
    }
  });
};
exports.updateUser = function(req, res){
  User.findOne({ _id: req.session.user })
  .exec(function(err, user) {
    console.log(req.body);
    user.set('level', user.level + 1);
    user.save(function(err) {
      if (err){
        res.session.error = err;
      } else {
	req.session.level = user.level;
        res.redirect('/');
      }
    });
  });
};
exports.deleteUser = function(req, res){
  User.findOne({ _id: req.session.user })
  .exec(function(err, user) {
    if(user){
      user.remove(function(err){
        if (err){
          req.session.msg = err;
        }
        req.session.destroy(function(){
          res.redirect('/login');
        });
      });
    } else{
      req.session.msg = "User Not Found!";
      req.session.destroy(function(){
        res.redirect('/login');
      });
    }
  });
};
