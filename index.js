const express = require("express");
const cors = require("cors");

const app = express();
app.use(cors());
app.use(express.json());

app.post("/login", (req, res) => {
  const { username, password } = req.body;
  if (username === "admin" && password === "1234") {
    return res.status(200).json({ message: "Giriş başarılı", token: "abc123" });
  } else {
    return res.status(401).json({ error: "Geçersiz kullanıcı adı veya şifre" });
  }
});

app.get("/", (req, res) => {
  res.send("Teftiş Portal Backend Aktif");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Sunucu ${PORT} portunda çalışıyor`);
});
