const express = require('express');
const router = express.Router();

const { userController : controller } = require('../controller/Controller')
const isAuth = require('../middleware/isAuth');
const isRefresh = require('../middleware/isRefresh');


router.post('/join', controller.UserJoin);
router.post('/login',controller.UserLogin);
router.post('/auth', isAuth, controller.AuthTest);
router.post('/refresh', isRefresh);

module.exports = router;