const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

const table_user = mongoose.Schema({
  username: { type: String, unique: true },
  name: { type: String },
  email: { type: String },
  password: { type: String },
  phone: { type: String },
  createdat: { type: Date, default: Date.now },
});

//antes de salvar, fazer a criptografia da senha
table_user.pre("save", function (next) {
  let user = this;
  if (!user.isModified("password")) {
    return next();
  }
  //quantidade de vezes que faz o calculo
  bcrypt.hash(user.password, 10, (erro, hashpassword) => {
    user.password = hashpassword;
    return next();
  });
});

module.exports = mongoose.model("user", table_user);
