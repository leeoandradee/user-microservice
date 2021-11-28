const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const User = require("./model/user");
const ManagerUser = require("./model/manageuser");
const create_token = require("./utils/token");
const { check, validationResult } = require("express-validator");
const auth = require("./middleware/auth");

const app = express();
app.use(express.json());

app.use(cors());

const url =
  "mongodb+srv://leeoandradee:BttT3RUtcAMtjYf@clusteruser.zrz7c.mongodb.net/myFirstDatabase?retryWrites=true&w=majority";

mongoose.connect(url, { useNewUrlParser: true, useUnifiedTopology: true });

app.post(
  "/user/signup",
  check("username").notEmpty().withMessage("username can not be empty"),
  check("name").notEmpty().withMessage("name can not be empty"),
  check("email").notEmpty().withMessage("email can not be empty"),
  check("email").isEmail().withMessage("invalid email"),
  check("password").notEmpty().withMessage("password can not be empty"),
  check("password")
    .isLength({
      min: 6,
    })
    .withMessage("password must have at least 6 characters"),
  check("phone").notEmpty().withMessage("phone can not be empty"),

  (req, res) => {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({
        success: false,
        errors: errors.array(),
      });
    }
    const data = new User(req.body);
    data
      .save()
      .then((success) => {
        res
          .status(201)
          .send({ output: `Novo usuário inserido`, payload: success });
      })
      .catch((error) => {
        console.log(error);
        res.status(500).send({ output: `Cadastro não realizado` });
      });
  }
);

app.post(
  "/user/login",
  check("username").notEmpty().withMessage("username can not be empty"),
  check("password").notEmpty().withMessage("password can not be empty"),
  (req, res) => {
    const username = req.body.username;
    const pswd = req.body.password;

    //localizar algo no banco
    User.findOne({ username: username }, (error, data) => {
      if (error) {
        return res
          .status(500)
          .send({ output: `Erro ao tentar localizar o usuário` });
      }
      if (!data) {
        return res.status(403).send({ output: `Usuário não localizado` });
      }

      bcrypt.compare(pswd, data.password, (error, data) => {
        if (error) {
          return res
            .status(500)
            .send({ output: `Erro interno na validação da senha` });
        }
        if (!data) {
          return res.status(403).send({ output: `A senha não é válida` });
        }

        const token = create_token(data._id, data.username);
        const info = new ManagerUser({
          userid: data._id,
          username: data.username,
          information: req.headers,
        });
        info.save();
        res.status(200).send({ output: `Autenticado`, payload: data, token });
      });
    });
  }
);

app.post("/user/password", auth, (req, res) => {
  const { username, currentPassword, newPassword } = req.body;

  User.findOne({ username: username }, (error, user) => {
    if (error) {
      return res
        .status(500)
        .send({ output: `Erro ao tentar localizar o usuário` });
    }
    if (!user) {
      return res.status(401).send({ output: `Usuário não localizado` });
    }

    bcrypt.compare(currentPassword, user.password, (error, data) => {
      if (error) {
        return res
          .status(500)
          .send({ output: `Erro interno na validação da senha` });
      }
      if (!data) {
        return res.status(403).send({ output: `A senha atual não é válida` });
      } else {
        user.password = newPassword;
        User(user)
          .save()
          .then((success) => {
            res.status(201).send({ output: `Senha atualizada com sucesso` });
          })
          .catch((error) => {
            console.log(error);
            res.status(500).send({ output: `Falha ao atualizar a senha` });
          });
      }
    });
  });
});

app.listen(4000, () => {
  console.log("Servidor online em http://localhost:4000");
});
