import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import env from "dotenv";
import bcryptjs from "bcryptjs";
import passport from "passport";
import { Strategy } from "passport-local";
import session from "express-session";

env.config();

const app = express();
const port = 5000;

const saltRounds = 10;
const bcrypt = bcryptjs;

app.use(
    session({
        secret: process.env.SECRET,
        resave: false,
        saveUninitialized: true,
        cookie: {
            secure: false
        }
    })
)

app.use("/public", express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }))

app.use(passport.initialize())
app.use(passport.session())

const db = new pg.Client({
    user: process.env.USER,
    password: process.env.PASSWORD,
    host: process.env.HOST,
    port: process.env.PORT,
    database: process.env.DATABASE
})

db.connect();

app.get("/", (req, res) => {
    res.render("index.ejs")
})

app.get("/sign_up", async (req, res) => {
    res.render("sign_up.ejs")
})

app.get("/sign_in", async (req, res) => {
    res.render("sign_in.ejs")
})

app.get("/success", async (req, res) => {
    res.render("success.ejs")
})

app.post(
    "/create-account", 
    passport.authenticate(
        "local", {
            successRedirect: "/secret",
            failureRedirect: "/"
        }
    )
)

passport.use(
    "local", 
    new Strategy(async function verify(username, password, cb) {
        const email = username;
        try {
            const dataInDB = await db.query(
                "SELECT * FROM users WHERE email = $1",
                [email]
            )

            if (dataInDB.rows.length === 1) {
                return cb("User Exists!!!");
            }

            bcrypt.hash(password, saltRounds, async (err, hash) => {
                    if (err) {
                        return cb(err)
                    }
                    
                    const user = await db.query(
                        `INSERT INTO users (email, password)
                            VALUES ($1, $2)`, 
                        [email, hash]
                    );
                    
                    return cb(null, user.rows[0])
                }
            )
        } catch (err) {
            return cb(err)
        }
    })
)

passport.serializeUser((user, cb) => {
    cb(null, user);
})

passport.deserializeUser((user, cb) => {
    cb(null, user);
})

app.listen(port, () => {
    console.log("Server Running on Port:", port)
})
