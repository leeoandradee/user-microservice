const jwt = require("jsonwebtoken");
const conf = require("../config/config");

const auth = (req, res, next) => {
  const token_created = req.headers.authorization;

  if (!token_created) {
    return res.status(401).send({ output: `token não informado` });
  }

  const parts = token_created.split(" ");

  if (!parts.length === 2) {
    return res.status(401).send({ error: "erro no token" });
  }

  const [scheme, token] = parts;

  if (!/^Bearer$/i.test(scheme)) {
    return res.status(401).send({ error: "token mal formado" });
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
