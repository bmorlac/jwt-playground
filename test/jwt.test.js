import jwt, { JsonWebTokenError } from 'jsonwebtoken';
import fs from 'fs';
import path from 'path';

suite('JWT tokens', () => {
  const SECRET = 'topsecret';

  test('should create a valid token with the HMAC algorithm', () => {
    const user = { id: 42 };
    const token = jwt.sign(user, SECRET);
    expect(token).to.be.a('string');
  });

  test('should decode a token created with the HMAC algorithm', () => {
    const user = { id: 42 };
    const token = jwt.sign(user, SECRET);

    const decoded = jwt.decode(token)
    expect(decoded).to.be.an('object').that.has.all.keys('id', 'iat');
  });

  test('should not verify the signature using decode()', () => {
    const user = { id: 42 };
    const fakeToken = jwt.sign(user, 'fakesecret');
    const decoded = jwt.decode(fakeToken);
    expect(decoded).to.be.an('object').that.has.all.keys('id', 'iat');
  });

  test('should verify the signature using verify()', () => {
    const user = { id: 42 };
    const fakeToken = jwt.sign(user, 'fakesecret');
    expect(() => jwt.verify(fakeToken, SECRET)).to.throw(JsonWebTokenError, 'invalid signature');
  });

  test('should create a valid token with the RSA algorithm', () => {
    const user = { id: 42 };
    const privateKey = fs.readFileSync(path.join(__dirname, '..', 'private_key.pem'));
    const token = jwt.sign(user, privateKey, { algorithm: 'RS256' });

    const publicKey = fs.readFileSync(path.join(__dirname, '..', 'public_key.pem'));
    const decoded = jwt.verify(token, publicKey, { algorithms: ['RS256'] });

    expect(privateKey).to.be.an.instanceOf(Buffer);
    expect(publicKey).to.be.an.instanceOf(Buffer);
    expect(decoded).to.be.an('object').that.has.all.keys('id', 'iat');
  });

  test('should create a valid token with the RSA algorithm and public key provided as a string', () => {
    const user = { id: 42 };
    const privateKey = fs.readFileSync(path.join(__dirname, '..', 'private_key.pem'));
    const token = jwt.sign(user, privateKey, { algorithm: 'RS256' });

    const decoded = jwt.verify(token, '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAv/PypsPfYIDwHgyZzr9jv3Sy14s1JIyKpYAIVN00cImO6KNsQLvjbBRy31saB8OO7fvCnYtrv+979rMffdDQft9T2HLD5l88aodLMiu65T8iLoGlHwKbcCxBxluS/kEH/XV5wQHM08f/yOLU66GMSa1oQC6oocPoCNd2VJnQgj4hot67aNygIFWlkaKkWTFUidOmiebtf4eDi2YrMTiJdsrK83oqXPiIwqagGS8Bb879cca7QnHffXvcSw9KdTPjfmgcYJxM1vBxfyvLnN1+xvsr3yD9wp+XSdynUBNmrTrENBfUJ1oDO+CtMMjoEdqUbEMi1ymAusI0dfqIrK7ofQIDAQAB\n-----END PUBLIC KEY-----', { algorithms: ['RS256'] });

    expect(decoded).to.be.an('object').that.has.all.keys('id', 'iat');
  });
});
