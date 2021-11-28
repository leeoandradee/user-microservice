const jwt = require("jsonwebtoken");
const conf = require("../config/config");

const auth = (req, res, next) => {
  let token_created = req.headers.authorization;
  token_created = token_created.split(' ')[1];

  if (!token_created) {
    return res.status(401).send({ output: `Access denied` });
  }

  jwt.verify(token_created, conf.jwt_key, (error, data) => {
    if (error) {
      return res.status(401).send({ output: `Token fail ->${error}` });
    }
    req.content = {
      id: data._id,
      user: data.username,
    };
    return next();
  });
};
module.exports = auth;
