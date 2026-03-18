let userController = require("../controllers/users");
let jwt = require("jsonwebtoken");
const fs = require("fs");
const path = require("path");

// Đọc Public Key để giải mã (Xác thực RS256)
const publicKey = fs.readFileSync(
  path.join(__dirname, "../public.pem"),
  "utf8",
);

module.exports = {
  CheckLogin: async function (req, res, next) {
    try {
      let authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).send({
          message: "ban chua dang nhap (hoac thieu Bearer)",
        });
      }

      // Cắt chữ "Bearer " lấy token
      let token = authHeader.split(" ")[1];

      // CẬP NHẬT RS256: Giải mã bằng publicKey
      let result = jwt.verify(token, publicKey, { algorithms: ["RS256"] });

      let user = await userController.GetAnUserById(result.id);
      if (!user) {
        return res.status(404).send({
          message: "khong tim thay user",
        });
      }
      req.user = user;
      next();
    } catch (error) {
      console.log("Loi Token: ", error.message);
      res.status(401).send({
        message: "ban chua dang nhap (hoac token sai/het han)",
      });
    }
  },
};
