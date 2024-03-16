const cheerio = require('cheerio')
const forge = require('node-forge')

// Hàm để trích xuất các đường dẫn từ nội dung HTML
const extractLinks = (html) => {
    const $ = cheerio.load(html);
    const links = [];
    
    $('a').each((index, element) => {
        links.push($(element).attr('href'));
    });
    
    return links;
}

// Hàm để kiểm tra xem đường dẫn có sử dụng HTTPS hay không
const checkHttpsUsage = (links) => {
    const nonSecureLinks = [];
    links.forEach(link => {
        if (link && !link.startsWith('https://') && link.startsWith('http://')) {
            nonSecureLinks.push(link);
        }
    });

    return nonSecureLinks
}

function isValidSslCertString(sslCertString, type) {
    if (!sslCertString || typeof sslCertString !== 'string') {
        return false;
    }
    try {
        if(type === 'crt') forge.pki.certificateFromPem(sslCertString);
        else if (type === 'csr') forge.pki.certificationRequestFromPem(sslCertString);
        else if (type === 'privateKey') forge.pki.privateKeyFromPem(sslCertString);
        else return false
        return true;
    } catch (error) {
        return false;
    }
}

module.exports = {
    extractLinks,
    checkHttpsUsage,
    isValidSslCertString
}