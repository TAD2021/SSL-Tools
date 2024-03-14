const express = require('express')
const bodyParser = require('body-parser')

const app = express()

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({extended: true}))


app.get('/', (req, res) => {
    res.json({data: 'Hello world'})
})

const port = process.env.PORT || 8001

app.listen(port, () => {
    console.log(`App is running at the port ${port}`)
})