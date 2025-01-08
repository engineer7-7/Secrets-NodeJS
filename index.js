// import libraries
import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import {Strategy} from "passport-local";
import env from "dotenv";
import GoogleStrategy from "passport-google-oauth2";


// create an instance of express and initialize the port
const app = express();
const port = 3000;

// initialize env
env.config();

// connect to the db
const db = new pg.Client({
        user: process.env.DATABASE_USER,
        password: process.env.DATABASE_PASSWORD,
        host: process.env.DATABASE_HOST,
        port: process.env.DATABASE_PORT,
        database: process.env.DATABASE_NAME,

    }
);
db.connect();

app.use(bodyParser.urlencoded({extended: true}));
app.use(express.static("public"));
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
        maxAge: 1000 * 60 * 60
    }
}));

app.use(passport.initialize());
app.use(passport.session(undefined));

// array to store the users from the user table
let list_users = [];

// display the main page
app.get("/", (req, res) => {
    db.query(" SELECT * FROM users", (err, result) => {
        if (err) {
            console.log("Error executing query", err.stack);
        } else {
            list_users = result.rows;
            console.log(list_users);

        }
    })
    res.render("home.ejs");
});

app.get('/secrets', (req, res) => {
    res.render("secrets.ejs", {secret: null});
});

app.get('/submit', (req, res) => {
    res.render("submit.ejs");
})

app.post('/login', passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login"
}));

app.get('/logout', (req, res) => {
    req.logout(function (err) {
        if (err) {
            return err;
        } else {
            console.log("Successfully logged out");
            res.redirect("/");
        }
    });
});

// display the login page
app.get("/login", (req, res) => {
    res.render("login.ejs");
});

// display the register page
app.get("/register", (req, res) => {
    res.render("register.ejs");
});


// get route to connect with Google
app.get('/auth/google', passport.authenticate("google", {
    scope: ["profile", "email"],
}))

app.get('/auth/google/secrets', passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login"
}))

// create a new user
app.post("/register", async (req, res) => {
    const email = req.body.username;
    const password = req.body.password;

    function filter_email(list) {
        return list.email === email; // can also be done using SQL query (where email = email)
    }

    let filtered_emails = list_users.filter(filter_email);
    console.log(filtered_emails);

    if (email && password) {
        console.log(email + "\n" + password);
        if (filtered_emails.length > 0) {
            console.log("This email already exists. Log in instead!");
            res.redirect("/login");
        } else {
            try {
                const hashed_password = await bcrypt.hash(password, 12);
                const query = "INSERT INTO users(email, password) VALUES ($1, $2) RETURNING *";
                const values = [email, hashed_password];
                db.query(query, values, (err) => {
                    if (err) {
                        console.log("An error has occurred", err.stack);
                    } else {
                        console.log("Values have been inserted successfully.");
                        res.redirect("/");
                    }
                })
            } catch (err) {
                console.log("An error has occurred", err.stack);
            }
        }
    } else {
        res.send("No data received");
    }
});

// post route to submit a secret
app.post('/submit', async (req, res) => {
    const secret = req.body.secret;
    console.log(secret);
    if (!secret) {
        res.send("Error");
    } else {
        res.render("secrets.ejs", {secret: secret});
    }

})

passport.use(
    new Strategy(async function verify(username, password, callback) {
        console.log("Entering strategy function");
        // console.log(username); // email from the login form
        // console.log(password); // password from the login form

        try {
            const result = await db.query("SELECT * FROM users WHERE email = $1", [username]);
            if (result.rows.length > 0) {
                const user = result.rows[0];
                const hashedPassword = user.password;
                bcrypt.compare(password, hashedPassword, (err, result) => {
                    if (err) {
                        return callback(err);
                    } else {
                        if (result) {
                            return callback(null, user);
                        } else {
                            console.log("Wrong credentials");
                            return callback(null, false);
                        }
                    }
                });
            } else {
                return callback("User not found.");
            }
        } catch (err) {
            return callback(err);
        }
    }));


passport.use("google", new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CLIENT_CALLBACKURL,
    userProfileURL: process.env.USER_PROFILE_URL
}, async (accessToken, refreshToken, profile, callback) => {
    console.log(profile);
    try {
        const result = await db.query("SELECT * FROM users WHERE email = $1", [profile.email]);
        if (result.rows.length === 0) {
            const new_user = await db.query("INSERT INTO users (email, password) VALUES ($1, $2)", [profile.email, "google"]);
            return callback(null, new_user.rows[0]);
        } else {
            return callback(null, result.rows[0]);
        }

    } catch (err) {
        callback(err);
    }
}))

passport.serializeUser((user, callback) => {
    callback(null, user);
});

passport.deserializeUser((user, callback) => {
    callback(null, user);
})

app.listen(port, () => {
    console.log(`Server running on port: http://localhost:${port}/ `);
});
