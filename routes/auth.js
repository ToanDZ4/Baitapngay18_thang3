let express = require("express");
let router = express.Router();
let userController = require("../controllers/users");
let bcrypt = require("bcrypt");
const { CheckLogin } = require("../utils/authHandler");
let jwt = require("jsonwebtoken");
const fs = require("fs");
const path = require("path");

// Đọc Private Key để mã hoá token (RS256)
const privateKey = fs.readFileSync(
  path.join(__dirname, "../private.pem"),
  "utf8",
);

router.post("/register", async function (req, res, next) {
  try {
    let { username, password, email } = req.body;
    let newUser = await userController.CreateAnUser(
      username,
      password,
      email,
      "69b1265c33c5468d1c85aad8",
    );
    res.send(newUser);
  } catch (error) {
    res.status(404).send({
      message: error.message,
    });
  }
});

router.post("/login", async function (req, res, next) {
  try {
    let { username, password } = req.body;
    let user = await userController.GetAnUserByUsername(username);
    if (!user) {
      res.status(404).send({ message: "thong tin dang nhap khong dung" });
      return;
    }
    if (user.lockTime > Date.now()) {
      res.status(404).send({ message: "ban dang bi ban" });
      return;
    }
    if (bcrypt.compareSync(password, user.password)) {
      user.loginCount = 0;
      await user.save();

      // CẬP NHẬT RS256: Ký token bằng privateKey
      let token = jwt.sign(
        {
          id: user._id,
        },
        privateKey,
        {
          algorithm: "RS256", // Khai báo thuật toán
          expiresIn: "1d",
        },
      );
      res.send(token);
    } else {
      user.loginCount++;
      if (user.loginCount == 3) {
        user.loginCount = 0;
        user.lockTime = Date.now() + 3600 * 1000;
      }
      await user.save();
      res.status(404).send({ message: "thong tin dang nhap khong dung" });
    }
  } catch (error) {
    res.status(404).send({ message: error.message });
  }
});

router.get("/me", CheckLogin, function (req, res, next) {
  res.send(req.user);
});

// HÀM MỚI: Đổi mật khẩu (Yêu cầu đăng nhập thông qua CheckLogin)
router.post("/change-password", CheckLogin, async function (req, res, next) {
  try {
    let { oldpassword, newpassword } = req.body;

    // 1. Validate dữ liệu đầu vào
    if (!oldpassword || !newpassword) {
      return res
        .status(400)
        .send({ message: "Vui lòng nhập đầy đủ mật khẩu cũ và mới" });
    }
    if (newpassword.length < 6) {
      return res
        .status(400)
        .send({ message: "Mật khẩu mới phải có ít nhất 6 ký tự" });
    }
    if (oldpassword === newpassword) {
      return res
        .status(400)
        .send({ message: "Mật khẩu mới không được trùng mật khẩu cũ" });
    }

    // 2. Lấy thông tin user (đã được CheckLogin gắn vào req.user)
    let user = req.user;

    // 3. Kiểm tra mật khẩu cũ có khớp với DB không
    if (!bcrypt.compareSync(oldpassword, user.password)) {
      return res.status(400).send({ message: "Mật khẩu cũ không chính xác" });
    }

    // 4. Mã hoá mật khẩu mới và lưu vào database
    const salt = bcrypt.genSaltSync(10);
    const hashPassword = bcrypt.hashSync(newpassword, salt);

    user.password = hashPassword;
    await user.save();

    res.send({ message: "Đổi mật khẩu thành công!" });
  } catch (error) {
    res.status(500).send({ message: error.message });
  }
});

module.exports = router;
