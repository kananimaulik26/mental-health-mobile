const express = require("express");
const app = express();
const dotenv = require("dotenv");
dotenv.config();
const IndexRoute = require('./routes/IndexRoute');

app.use(express.json());
app.use('/',IndexRoute)

app.listen(process.env.PORT || 5000, () => {
  console.log(`Server is running on port ${process.env.PORT}`);
});
