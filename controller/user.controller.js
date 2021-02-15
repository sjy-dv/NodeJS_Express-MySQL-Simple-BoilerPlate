const db = require('../database/db');
const argon2 = require('argon2');
const { createToken, createRefreshToken } = require('../utils/jwt');


module.exports = ( function () {

    const U = {};

    U.UserJoin = async function(req, res){
        try {
            const password = await argon2.hash(req.body.password);
            const data = [req.body.username, password];
            console.log(data);
            const sql = 'insert into member(username, password) values(?,?)';
            const conn = await db.getConnection();
            await conn.query(sql,data);
            conn.release();
            res.status(200).send('success');
        } catch (error) {
            throw res.send("DB ERROR");
        }
    }

    U.UserLogin = async function (req,res) {
        try {
            const data = [req.body.username]
            const sql = 'select * from member where username = ?';
            const conn = await db.getConnection();
            const [rows] = await conn.query(sql,data);
            conn.release();
            console.log(rows[0].password);
            const compare = await argon2.verify(rows[0].password, req.body.password);
            if(compare === true){
                const token = createToken(rows[0].username);
                const rtoken = createRefreshToken(rows[0].username);
                res.send([token, rtoken]);
            }else{
               throw res.send('PASSWORD WRONG'); //login failed
            }
        } catch (error) {
            throw res.send("DB ERROR");
        }
    }

    U.AuthTest = async function(req,res){
        try {
            res.send('auth token check ok');
        } catch (error) {
            throw res.send("DB ERROR");
        }
    };

    return U;

})();

