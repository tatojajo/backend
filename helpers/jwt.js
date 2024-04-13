const jwt = require("jsonwebtoken");

function authJwt(req, res, next) {
 
  if (!req || !req.headers || !req.headers.authorization) {
    return res.status(401).json({ message: "Unauthorized: No token provided" });
  }

  const token = req.headers.authorization;

  const secret = process.env.JWT_KEY;

  jwt.verify(token, secret, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: "Unauthorized: Invalid token" });
    }


    req.user = decoded;

    next();
  });
}

module.exports = authJwt;
