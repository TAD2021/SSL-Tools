const countriesData = require('../data/countries.json')
const dns = require('dns')

const isValidDomain = (domain) => {
    const domainRegex = /^(?:[-A-Za-z0-9]+\.)+[-A-Za-z0-9]{2,}(?:\.[A-Za-z]{2,})?$/;
    const unicodeRegex = /[\u00A1-\uFFFF]/;

    if (domainRegex.test(domain)) {
        return true;
    }

    // Kiểm tra xem domain có chứa các ký tự Unicode không
    if (unicodeRegex.test(domain)) {
        try {
            // Chuyển đổi domain thành dạng ASCII
            const asciiDomain = new URL(`http://${domain}`).hostname;
            return domainRegex.test(asciiDomain);
        } catch (error) {
            return false; // Xảy ra lỗi khi chuyển đổi domain
        }
    }

    return false;
}

const isCountryCodeValid = (countryCode) => {
    // Chuyển đổi mã quốc gia thành chữ in hoa để so sánh
    const upperCaseCountryCode = countryCode.toUpperCase();
    const keys = Object.keys(countriesData);

    // Tìm kiếm mã quốc gia trong tập dữ liệu
    const foundCountry = keys.find(country => country === upperCaseCountryCode);
    return !!foundCountry;
}

const isValidEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email)
}

const addHttpPrefix = (url) => {
    if (!url.startsWith('http://') && !url.startsWith('https://')) {
        return 'http://' + url;
    }
    return url;
}

const checkIpAddresses = (domain) => {
    return new Promise((resolve, reject) => {
        dns.resolve(domain, 'A', (err, addresses) => {
            if (err) {
                resolve('')
            } else {
                resolve(addresses[0])
            }
        })
    })
}

module.exports = {
    isCountryCodeValid,
    isValidDomain,
    isValidEmail,
    addHttpPrefix,
    checkIpAddresses
}