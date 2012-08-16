var should = chai.should();


describe('encryption ', function () {
  describe('asymmetric', function () {
    var n, e = "03", d, p, q, dmp1, dmq1, coeff;
    var textToEncrypt =  '01234567890123456';
    var encryptedText;

    it('should generate a key', function (done) {
      key = new RSAKey();
      key.generateAsync(256, e, function () {
        n = linebrk(key.n.toString(16),64);
        d = linebrk(key.d.toString(16),64);
        p = linebrk(key.p.toString(16),64);
        q = linebrk(key.q.toString(16),64);
        dmp1 = linebrk(key.dmp1.toString(16),64);
        dmq1 = linebrk(key.dmq1.toString(16),64);
        coeff = linebrk(key.coeff.toString(16),64);

        done();
      })
    })

    it ('should encrypt some text', function(done) {
      var rsa =  new RSAKey();
      rsa.setPublic(n, e);

      encryptedText = rsa.encrypt(textToEncrypt);
      done();
    });

    it ('should decrypt the text', function(done) {
      var rsa =  new RSAKey();
      rsa.setPrivateEx(n,e,d,p,q,dmp1,dmq1,coeff);

      var decryptedText = rsa.decrypt(encryptedText);
      decryptedText.should.equal(textToEncrypt);
      done();
    });
  })

  describe ('symmetric sjcl', function(){
    var password = '23190crgudodhntetgeaoukbpcr';
    var symTextToEncrypt = 'this could be a message that someone sends to someone';
    it('should encrypt and decrypt 10000 messages', function(done) {
      for(var i=0;i<10000;i++) {

        var enc =  sjcl.encrypt(password, symTextToEncrypt, {ks:256});
        var cipher = enc;//.match(/"ct":"([^"]*)"/)[1]; //"
        var dec = sjcl.decrypt(password,cipher, {ks:256});
        dec.should.equal(symTextToEncrypt);

      }


      done();
    })
  })

  describe ('symmetric gibberish-aes', function(){
    var password = '23190crgudodhntetgeaoukbpcr';
    var symTextToEncrypt = 'this could be a message that someone sends to someone';
    it('should encrypt and decrypt 10000 messages', function(done) {
      var cipher;
      for(var i=0;i<10000;i++) {
        cipher = GibberishAES.enc(symTextToEncrypt, password);


        GibberishAES.dec(cipher,password).should.equal(symTextToEncrypt);

      }


      done();
    })
  })


})
