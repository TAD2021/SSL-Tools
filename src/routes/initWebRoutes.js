const express = require('express')
const SSL_Controller = require('../controllers/SSL_Controller')
const { validateInput } = require('../middlewares/SSL_Middleware')
const { uploadPEM, uploadDER, uploadMultiPEM, uploadPFX, uploadP7B, uploadMultiP7B } = require('../middlewares/uploadMiddleware')

const router = express.Router()

const initWebRoutes = (app) =>  {
    router.get('/SSL/SSLCsrGenerator', validateInput, SSL_Controller.csrGenerator)
    router.post('/SSL/SSLCsrDecode', SSL_Controller.csrDecode)
    router.post('/SSL/SSLCrtDecode', SSL_Controller.sslCrtDecode)
    router.get('/SSL/SSLWhyNoPadlock', SSL_Controller.checkSSL)
    router.post('/SSL/SSLCheckMatchCSR', SSL_Controller.sslCheckMatchCSR)
    router.post('/SSL/SSLCheckMatchKey', SSL_Controller.sslCheckMatchKey)
    router.get('/SSL/SSLInfoCheck', SSL_Controller.sslInfoCheck)
    router.post('/SSL/SSLFileConvert/PEMtoDER', uploadPEM, SSL_Controller.convertPEMtoDER)
    router.post('/SSL/SSLFileConvert/PEMtoPFX', uploadMultiPEM, SSL_Controller.convertPEMtoPFX)
    router.post('/SSL/SSLFileConvert/PEMtoP7B', uploadMultiPEM, SSL_Controller.convertPEMtoP7B)
    router.post('/SSL/SSLFileConvert/DERtoPEM', uploadDER, SSL_Controller.convertDERtoPEM)
    router.post('/SSL/SSLFileConvert/PFXtoPEM', uploadPFX, SSL_Controller.convertPFXtoPEM)
    router.post('/SSL/SSLFileConvert/P7BtoPEM', uploadP7B, SSL_Controller.convertP7BtoPEM)
    router.post('/SSL/SSLFileConvert/P7BtoPFX', uploadMultiP7B, SSL_Controller.convertP7BtoPFX)
    router.get('/SSL/CAAGenerator', SSL_Controller.CAAGenerator)
    return app.use('/',router)
}

module.exports = initWebRoutes