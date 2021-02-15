const express = require('express');
const app = express();
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
require('dotenv').config();
const port = process.env.PORT || 8081;
const user = require('./routes/user.routes');


app.use(cors());
app.use(helmet());
app.use(compression());
app.use(express.json());
app.use(express.urlencoded({extended:false}));

app.use('/user', user);

app.listen(port, () => {
    console.log(`server on ${port}`);
})