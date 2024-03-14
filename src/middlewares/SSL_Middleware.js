const {isCountryCodeValid, isValidDomain, isValidEmail} = require('../utils/commonServices')

const validateInput = (req, res, next) => {
    const inputData = req.query;
    const { commonName, domainType, organizationName, organizationalUnitName, countryName, localityName, stateOrProvinceName, emailAddress, keySize, encryptionType } = inputData;

    if (!commonName || !domainType || !countryName || !emailAddress) {
        return res.status(400).json({ status: false, message: 'commonName, domainType, countryName, and emailAddress are required' });
    }

    // Kiểm tra tính hợp lệ của email và mã quốc gia
    if (!isValidEmail(emailAddress)) {
        return res.status(400).json({ status: false, message: 'emailAddress is not valid' });
    }
    if (!isCountryCodeValid(countryName)) {
        return res.status(400).json({ status: false, message: 'countryName is not valid' });
    }
    if (!isValidDomain(commonName)) {
        return res.status(400).json({ status: false, message: 'commonName is not valid' });
    }

    req.validatedData = {
        commonName,
        domainType,
        organizationName,
        organizationalUnitName,
        countryName,
        localityName,
        stateOrProvinceName,
        emailAddress,
        keySize: keySize || 2048,
        encryptionType: encryptionType || 'sha256'
    };

    // Chuyển tiếp vaò controller
    next();
}

module.exports = {
    validateInput
};
