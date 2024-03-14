const express = require('express')
const bodyParser = require('body-parser')
const multer = require('multer')
const cors = require('cors')

const initWebRoutes = require('./src/routes/initWebRoutes')

const app = express()

app.use(cors());

//use body-parser to post data
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({extended: true}))

//init all web routes
initWebRoutes(app)

app.use((err, req, res, next) => {
    if (err instanceof multer.MulterError) {
        // Multer error
        return res.status(400).json({ status: false, message: err.message });
    } else if (err) {
        // Other errors
        return res.status(500).json({ status: false, error: err.message });
    } else {
        next();
    }
});

const port = process.env.PORT || 8001

app.listen(port, () => {
    console.log(`App is running at the port ${port}`)
})