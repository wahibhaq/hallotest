var crypto = require("crypto")

function encrypt(text){
  var cipher = crypto.createCipher('aes-256-cbc','d6F3Efeq')
  var crypted = cipher.update(text)
  crypted += cipher.final();
  return crypted;
}

function decrypt(text){
  var decipher = crypto.createDecipher('aes-256-cbc','d6F3Efeq')
  var dec = decipher.update(text)
  dec += decipher.final();
  return dec;
}

var hw = encrypt(new Buffer("hello world"))
console.log (decrypt(hw));