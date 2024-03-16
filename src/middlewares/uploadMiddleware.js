const multer = require('multer');

const allowedExtensions = (extensions) => (req, file, cb) => {
    const fileExtension = '.' + file.originalname.split('.').pop().toLowerCase();
    if (extensions.includes(fileExtension)) {
        cb(null, true);
    } else {
        cb(new Error(`Only ${extensions.join(', ')} files are allowed`));
    }
};
  
const uploadPEM = multer({
    storage: multer.diskStorage({}),
    fileFilter: allowedExtensions([ '.pem', '.crt', '.cer', '.key' ]),
}).single('file');
  
const uploadDER = multer({
    storage: multer.diskStorage({}),
    fileFilter: allowedExtensions([ '.der', '.cer' ]),
}).single('file');

const uploadMultiPEM = multer({
    storage: multer.diskStorage({}),
    fileFilter: allowedExtensions(['.pem', '.crt', '.cer', '.key']),
}).fields([
    { name: 'certificate', maxCount: 1 },
    { name: 'privateKey', maxCount: 1 },
    { name: 'caBundle' }
]);

const uploadPFX = multer({
    storage: multer.diskStorage({}),
    fileFilter: allowedExtensions([ '.pfx', '.p12' ]),
}).single('file');

const uploadP7B = multer({
    storage: multer.diskStorage({}),
    fileFilter: allowedExtensions([ '.p7b', '.p7c' ]),
}).single('file');

const uploadMultiP7B = multer({
    storage: multer.diskStorage({}),
    fileFilter: (req, file, cb) => {
        // Define allowed extensions based on field name
        if (file.fieldname === 'p7b') {
            allowedExtensions([ '.p7b', '.p7c' ])(req, file, cb);
        } else if (file.fieldname === 'privateKey' || file.fieldname === 'caBundle') {
            allowedExtensions(['.pem', '.crt', '.cer', '.key'])(req, file, cb);
        } else {
            cb(new Error('Invalid field name'));
        }
    }
}).fields([
    { name: 'p7b', maxCount: 1 },
    { name: 'privateKey', maxCount: 1 },
    { name: 'caBundle' }
]);

module.exports = {
    uploadPEM,
    uploadDER,
    uploadMultiPEM,
    uploadPFX,
    uploadP7B,
    uploadMultiP7B
}