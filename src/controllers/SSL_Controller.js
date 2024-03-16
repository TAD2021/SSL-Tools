const forge = require('node-forge')
const puppeteer = require('puppeteer')
const {exec} = require('child_process');
const axios = require('axios')
const fs = require('fs')

const {addHttpPrefix, isValidDomain, checkIpAddresses} = require('../utils/commonServices')
const {extractLinks, checkHttpsUsage, isValidSslCertString} = require('../utils/sslServices');

const ALGORITHM = require('../enums/algorithm')
const VALID_SUPPLIER = require('../enums/suppliers')
const VALID_WILDCARD = require('../enums/wildcards')

// Tạo CSR và private key
const csrGenerator = (req,res) => {
    // Các thông tin đầu vào
    /**
     * Tên miền cần được mã hóa SSL*: commonName
     * Loại tên miền*: domainType
     * Tên công ty: organizationName
     * Tên bộ phận: organizationalUnitName
     * Mã quốc gia*: countryName
     * Thành phố: localityName
     * Quận/huyện: stateOrProvinceName
     * Email quản lý*: emailAddress
     * Key Size: keySize
     * Loại mã hóa: encryptionType
     */
    // ==> Những tham số có dấu *: bắt buộc phải có
    const { 
        commonName, domainType, organizationName, organizationalUnitName, countryName, 
        localityName, stateOrProvinceName, emailAddress, keySize, encryptionType 
    } = req.validatedData;

    try{
        const arrSubject = []
        if (domainType === "www") {
            arrSubject.push({name: 'commonName', value: 'www.' + commonName})
        } else if (domainType === "subdomain") {
            arrSubject.push({name: 'commonName', value: commonName})
        } else if (domainType === "*") {
            arrSubject.push({name: 'commonName', value: '*.' + commonName})
        } else {
            return res.status(400).json({status: false, message: 'domainType is not valid'})
        }

        arrSubject.push(
            { name: 'countryName', value: countryName}, 
            { name: 'emailAddress', value: emailAddress}
        )

        if(organizationName){
            arrSubject.push({name: 'organizationName', value: organizationName})
        }
        if(organizationalUnitName){
            arrSubject.push({name: 'organizationalUnitName', value: organizationalUnitName})
        }
        if(localityName){
            arrSubject.push({name: 'localityName', value: localityName})
        }
        if(stateOrProvinceName){
            arrSubject.push({name: 'stateOrProvinceName', value: stateOrProvinceName})
        }

        // Tạo cặp khóa RSA với độ dài bit 2048, 3072 hoặc 4096
        const validKeySize = [2048, 3072, 4096]
        if(!validKeySize.includes(parseInt(keySize))){
            return res.status(400).json({
                status: false,
                message: 'KeySize is not valid'
            })
        }
        const keyPair = forge.pki.rsa.generateKeyPair({ bits: parseInt(keySize) })

        // Tạo CSR
        const csr = forge.pki.createCertificationRequest();
        csr.publicKey = keyPair.publicKey
        csr.setSubject(arrSubject)

        // Ký CSR bằng Private Key, thêm mã hóa cho CSR
        // Loại mã hóa (encryptionType) bao gồm: sha256, sha384 và sha512
        const validEncryptionType = ['sha256', 'sha384', 'sha512']
        if(!validEncryptionType.includes(encryptionType)){
            return res.status(400).json({
                status: false,
                message: 'Encryption Type is not valid'
            })
        }
        csr.sign(keyPair.privateKey, forge.md[encryptionType].create())

        const csrPem = forge.pki.certificationRequestToPem(csr)
        const privateKeyPem = forge.pki.privateKeyToPem(keyPair.privateKey)

        return res.status(200).json({
            status: true,
            message: 'CSR has been processed successfully.',
            data: {
                CRS: csrPem,
                privateKey: privateKeyPem
            }
        })
    }catch(err){
        return res.status(500).json({
            status: false,
            message: err.message
        })
    }
}

// Đọc thông tin mã CSR
const csrDecode = (req, res) => {
    const csrPem = req.body.csrPem;

    try{
        if(!csrPem){
            return res.status(400).json({
                status: false,
                message: 'csrPem is required.'
            })
        }
        if (!isValidSslCertString(csrPem,'csr')) {
            return res.status(400).json({
                status: false,
                message: 'csrPem is not valid.'
            })
        }
        // Phân tích CSR
        const csr = forge.pki.certificationRequestFromPem(csrPem);

        // Lấy thông tin từ CSR
        const commonName = csr.subject.getField('CN') ? csr.subject.getField('CN').value : '';
        const countryName = csr.subject.getField('C') ? csr.subject.getField('C').value : '';
        const emailAddress = csr.subject.getField('E') ? csr.subject.getField('E').value : '';
        const organizationName = csr.subject.getField('O') ? csr.subject.getField('O').value : '';
        const organizationalUnitName = csr.subject.getField('OU') ? csr.subject.getField('OU').value : '';
        const localityName = csr.subject.getField('L') ? csr.subject.getField('L').value : '';
        const stateOrProvinceName = csr.subject.getField('ST') ? csr.subject.getField('ST').value : '';
        const keySize = csr.publicKey.n.bitLength();
        const signatureAlgorithm = csr.siginfo.algorithmOid;
        // some information about the signature algorithm: https://oidref.com/1.2.840.113549.1.1.11

        const csrInfo = {
            commonName,
            countryName,
            emailAddress,
            organizationName,
            organizationalUnitName,
            localityName,
            stateOrProvinceName,
            keySize,
            signatureAlgorithm,
        };

        res.status(200).json({
            status: true,
            message: 'CSR has been processed successfully.',
            data: csrInfo,
        });
    }catch(error){
        res.status(500).json({
            status: false,
            message: "Internal Server Error"
        });
    }
}

// Đọc thông tin mã CRT
const sslCrtDecode = async (req, res) => {
    //const sslCertString = `-----BEGIN CERTIFICATE-----\r\nMIIDETCCAfkCFCJz5EOzSMqintgVAOhFiZYAbw1xMA0GCSqGSIb3DQEBCwUAMEUx\r\nCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRl\r\ncm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMjQwMTE2MDExNDI0WhcNMjQwMjE1MDEx\r\nNDI0WjBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UE\r\nCgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOC\r\nAQ8AMIIBCgKCAQEA2ReMkrHG+8RioVZ14ZzBahNBadrhkaFdUll7yFRfjWOtPLkK\r\nsMVgH3jJxgp0Q1G/bEdrAgav/Q8CGD/v+Lwkb4RghBWNAe3K6Z/0KXk+4fgO8LWm\r\n1+IzTyDVfUWZVmbfTwaPGronrM7RJ4BDwUOCEzH7sAqZLE7gfNYg/tPGPZEfHsk2\r\nSJw8jJy+EAJIBx81WxO2uZGgZLPtKCP4UuQEGR8Zgy4eN6r+9Efd2351BRTYo3AJ\r\n4NrBognZBgLuR4GlDhk3adP3SU0vPywJ8EDYeXA+T8IRuIBy6YRLaAAK8iJmKw+M\r\nWfWm412B494lw96dwsne8bVpu50CimxFRHeBPQIDAQABMA0GCSqGSIb3DQEBCwUA\r\nA4IBAQAeecjRUG5o++GB1ly+mZVke22cx0lXYSsZctu8bHh2ERMOdevT6OR+gJoK\r\noqL02fnKApVlB2rJledysKBZXyw8WdtteK1wsJT4MZvGHDf8fqJYwbwySgrj79y7\r\nsXXaABJzHU6bdS6LoTi+Sygf6drRFLm8aAhGl+Ivo+c++gzfiKsFfWVAkQ2p9+1r\r\nx9zgW+GMW2/1BgcYJId9dMUIK2eRDmDfdpIA7SQYqFdBk5QVSoGccQkyWR9My6g/\r\nVG9VZqer311odOs8Kte0Y94XQIsvXS6j0OuIDLPTkmLaDTrs7gz7Pv6VW8/tVgkd\r\nBwW8MW9myHgowhyfHQ3CWqrj+HXK\r\n-----END CERTIFICATE-----\r\n`;
    const sslCertString = req.body.sslCrt
    try{
        if(!sslCertString){
            return res.status(400).json({
                status: false,
                message: 'SSL Certificate is required.'
            })
        }
        if (!isValidSslCertString(sslCertString,'crt')) {
            return res.status(400).json({
                status: false,
                message: 'SSL Certificate is not valid.'
            })
        }
        
        // Phân tích chứng chỉ SSL từ chuỗi
        const crt = forge.pki.certificateFromPem(sslCertString);

        const commonName = crt.subject.getField('CN') ? crt.subject.getField('CN').value : '';
        const countryName = crt.subject.getField('C') ? crt.subject.getField('C').value : '';
        const emailAddress = crt.subject.getField('E') ? crt.subject.getField('E').value : '';
        const organizationName = crt.subject.getField('O') ? crt.subject.getField('O').value : '';
        const organizationalUnitName = crt.subject.getField('OU') ? crt.subject.getField('OU').value : '';
        const localityName = crt.subject.getField('L') ? crt.subject.getField('L').value : '';
        const stateOrProvinceName = crt.subject.getField('ST') ? crt.subject.getField('ST').value : '';
        const keySize = crt.publicKey.n.bitLength();
        const signatureAlgorithmValue = crt.signatureOid;
        let signatureAlgorithmDisplay = '';
        if(signatureAlgorithmValue.startsWith('1.2.840.113549.1.1.')){
            const index = signatureAlgorithmValue.split('.').pop()
            if(index && index > 0 && index <= 14){
                signatureAlgorithmDisplay = ALGORITHM[index-1]
            }
        }
        const startDate = crt.validity.notBefore;
        const endDate = crt.validity.notAfter;
        const serialNumber = crt.serialNumber;
        const SANs = crt.getExtension('subjectAltName') ? crt.getExtension('subjectAltName').altNames.map(item => item.value).join(', ') : '';
        const attIssuer = crt.issuer.attributes;
        const issuers = attIssuer.map(issuer => {
            return issuer['shortName'].concat('=',issuer['value'])
        }).join(', ')
        const issuerName = crt.issuer.getField('CN') ? crt.issuer.getField('CN').value : '';

        const crtInfo = {
            commonName,
            SANs,
            organizationName,
            organizationalUnitName,
            emailAddress,
            countryName,
            localityName,
            stateOrProvinceName,
            signatureAlgorithmValue,
            signatureAlgorithmDisplay,
            keySize,
            serialNumber,
            issuerName,
            issuers,
            startDate,
            endDate,
        };

        return res.status(200).json({
            status: true,
            message: 'Read SSL Certificate successfully.',
            data: crtInfo
        })
    }catch(err){
        return res.status(500).json({
            status: false,
            message: "Internal Server Error"
        })
    }
}

// Tìm những đường dẫn (link) trong nội dung website chưa được chuyển thành https
const checkSSL = async (req, res) => {
    const downloadPage = async (url, callback) => {
        const browser = await puppeteer.launch({
            headless: "new",
            timeout: 0,
            args: ['--no-sandbox']
        });
        const page = await browser.newPage();
        await page.goto(url);
        const content = await page.content();
        await browser.close();
        const urls = callback(content);
        return urls
    }
    
    try{
        if(!req.query.url){
            return res.status(400).json({
                status: false,
                message: 'URL is required.'
            })
        }
        if(!isValidDomain(req.query.url)){
            return res.status(400).json({
                status: false,
                message: 'Domain is not valid'
            })
        }
        const url = addHttpPrefix(req.query.url)
        // Tải nội dung của trang web và kiểm tra các đường dẫn
        const data = await downloadPage(url, (html) => {
            const links = extractLinks(html);
            return checkHttpsUsage(links);
        });
        return res.status(200).json({
            status: true,
            message: 'Find links in website content successfully.',
            data
        })
    }catch(error){
        return res.status(500).json({
            status: false,
            message: "Internal Server Error"
        })
    }
}

// Kiểm tra trùng khớp bộ mã CSR va CRT
const sslCheckMatchCSR = (req, res) => {
    //const csrPem = `-----BEGIN CERTIFICATE REQUEST-----\r\nMIICijCCAXICAQAwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUx\r\nITAfBgNVBAoMGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDCCASIwDQYJKoZIhvcN\r\nAQEBBQADggEPADCCAQoCggEBANkXjJKxxvvEYqFWdeGcwWoTQWna4ZGhXVJZe8hU\r\nX41jrTy5CrDFYB94ycYKdENRv2xHawIGr/0PAhg/7/i8JG+EYIQVjQHtyumf9Cl5\r\nPuH4DvC1ptfiM08g1X1FmVZm308Gjxq6J6zO0SeAQ8FDghMx+7AKmSxO4HzWIP7T\r\nxj2RHx7JNkicPIycvhACSAcfNVsTtrmRoGSz7Sgj+FLkBBkfGYMuHjeq/vRH3dt+\r\ndQUU2KNwCeDawaIJ2QYC7keBpQ4ZN2nT90lNLz8sCfBA2HlwPk/CEbiAcumES2gA\r\nCvIiZisPjFn1puNdgePeJcPencLJ3vG1abudAopsRUR3gT0CAwEAAaAAMA0GCSqG\r\nSIb3DQEBCwUAA4IBAQALQwUiDUNvb6Vu43eQOaHK6rhD37/BpjVjZCR7o6puzqZc\r\numeWkly8/iRZH+YC/9W/1Cl6W8vte+S2AeXNJ7b8yhc52aLAdUjyFJXiX38uRjqm\r\n0dI673zOS8N+/XGpDJ59xPfdlrGTtTrKWVviiWu7bP0XeWk8NaYi/tYEcn73xcLg\r\nePtur9/HIUDtE54GmjTFPDd3c58U2dmQwqUXdnnYA2cm+nHnFnyaIBRaDyi3Be6i\r\nsVUqqMEsj2h5o2MmWTodSkXuxYoXmRHLOnBwMKgr1WPbxhqjy1oFymIA1NtK1OM5\r\nhdxOqc4YJ0veRMhQ4ohtuGAt7u7/Df8kTYyAoAIF\r\n-----END CERTIFICATE REQUEST-----\r\n`
    //const crtPem = `-----BEGIN CERTIFICATE-----\r\nMIIDETCCAfkCFCJz5EOzSMqintgVAOhFiZYAbw1xMA0GCSqGSIb3DQEBCwUAMEUx\r\nCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRl\r\ncm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMjQwMTE2MDExNDI0WhcNMjQwMjE1MDEx\r\nNDI0WjBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UE\r\nCgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOC\r\nAQ8AMIIBCgKCAQEA2ReMkrHG+8RioVZ14ZzBahNBadrhkaFdUll7yFRfjWOtPLkK\r\nsMVgH3jJxgp0Q1G/bEdrAgav/Q8CGD/v+Lwkb4RghBWNAe3K6Z/0KXk+4fgO8LWm\r\n1+IzTyDVfUWZVmbfTwaPGronrM7RJ4BDwUOCEzH7sAqZLE7gfNYg/tPGPZEfHsk2\r\nSJw8jJy+EAJIBx81WxO2uZGgZLPtKCP4UuQEGR8Zgy4eN6r+9Efd2351BRTYo3AJ\r\n4NrBognZBgLuR4GlDhk3adP3SU0vPywJ8EDYeXA+T8IRuIBy6YRLaAAK8iJmKw+M\r\nWfWm412B494lw96dwsne8bVpu50CimxFRHeBPQIDAQABMA0GCSqGSIb3DQEBCwUA\r\nA4IBAQAeecjRUG5o++GB1ly+mZVke22cx0lXYSsZctu8bHh2ERMOdevT6OR+gJoK\r\noqL02fnKApVlB2rJledysKBZXyw8WdtteK1wsJT4MZvGHDf8fqJYwbwySgrj79y7\r\nsXXaABJzHU6bdS6LoTi+Sygf6drRFLm8aAhGl+Ivo+c++gzfiKsFfWVAkQ2p9+1r\r\nx9zgW+GMW2/1BgcYJId9dMUIK2eRDmDfdpIA7SQYqFdBk5QVSoGccQkyWR9My6g/\r\nVG9VZqer311odOs8Kte0Y94XQIsvXS6j0OuIDLPTkmLaDTrs7gz7Pv6VW8/tVgkd\r\nBwW8MW9myHgowhyfHQ3CWqrj+HXK\r\n-----END CERTIFICATE-----\r\n`;
    const csrPem = req.body.csrPem
    const crtPem = req.body.crtPem

    try{
        if(!csrPem || !crtPem){
            return res.status(400).json({
                status: false,
                message: 'crsPem and crtPem are required.'
            })
        }
        if (!isValidSslCertString(csrPem,'csr')) {
            return res.status(400).json({
                status: false,
                message: 'csrPem is not valid.'
            })
        }
        if (!isValidSslCertString(crtPem,'crt')) {
            return res.status(400).json({
                status: false,
                message: 'crtPem is not valid.'
            })
        }
        // Phân tích CSR, CRT
        const csr = forge.pki.certificationRequestFromPem(csrPem);
        const crt = forge.pki.certificateFromPem(crtPem);

        // Trích xuất mã giữa CSR và CRT
        const csrPublicKeyOid = csr.publicKey.n.toString(10);
        const crtPublicKeyOid = crt.publicKey.n.toString(10);

        if (csrPublicKeyOid === crtPublicKeyOid) {
            return res.status(200).json({
                status: true,
                message: 'The codes between CSR and CRT match.'
            })
        } else {
            return res.status(400).json({
                status: false,
                message: 'The codes between CSR and CRT do not match.'
            })
        }
    }catch(err){
        return res.status(500).json({
            status: false,
            message: "Internal Server Error"
        })
    }
}

// Kiểm tra trùng khớp bộ mã CRT va private key
const sslCheckMatchKey = (req, res) => {
    //const crtPem = `-----BEGIN CERTIFICATE-----\r\nMIIDETCCAfkCFCJz5EOzSMqintgVAOhFiZYAbw1xMA0GCSqGSIb3DQEBCwUAMEUx\r\nCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRl\r\ncm5ldCBXaWRnaXRzIFB0eSBMdGQwHhcNMjQwMTE2MDExNDI0WhcNMjQwMjE1MDEx\r\nNDI0WjBFMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UE\r\nCgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOC\r\nAQ8AMIIBCgKCAQEA2ReMkrHG+8RioVZ14ZzBahNBadrhkaFdUll7yFRfjWOtPLkK\r\nsMVgH3jJxgp0Q1G/bEdrAgav/Q8CGD/v+Lwkb4RghBWNAe3K6Z/0KXk+4fgO8LWm\r\n1+IzTyDVfUWZVmbfTwaPGronrM7RJ4BDwUOCEzH7sAqZLE7gfNYg/tPGPZEfHsk2\r\nSJw8jJy+EAJIBx81WxO2uZGgZLPtKCP4UuQEGR8Zgy4eN6r+9Efd2351BRTYo3AJ\r\n4NrBognZBgLuR4GlDhk3adP3SU0vPywJ8EDYeXA+T8IRuIBy6YRLaAAK8iJmKw+M\r\nWfWm412B494lw96dwsne8bVpu50CimxFRHeBPQIDAQABMA0GCSqGSIb3DQEBCwUA\r\nA4IBAQAeecjRUG5o++GB1ly+mZVke22cx0lXYSsZctu8bHh2ERMOdevT6OR+gJoK\r\noqL02fnKApVlB2rJledysKBZXyw8WdtteK1wsJT4MZvGHDf8fqJYwbwySgrj79y7\r\nsXXaABJzHU6bdS6LoTi+Sygf6drRFLm8aAhGl+Ivo+c++gzfiKsFfWVAkQ2p9+1r\r\nx9zgW+GMW2/1BgcYJId9dMUIK2eRDmDfdpIA7SQYqFdBk5QVSoGccQkyWR9My6g/\r\nVG9VZqer311odOs8Kte0Y94XQIsvXS6j0OuIDLPTkmLaDTrs7gz7Pv6VW8/tVgkd\r\nBwW8MW9myHgowhyfHQ3CWqrj+HXK\r\n-----END CERTIFICATE-----\r\n`;
    //const privateKeyPem = `-----BEGIN PRIVATE KEY-----\r\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDZF4ySscb7xGKh\r\nVnXhnMFqE0Fp2uGRoV1SWXvIVF+NY608uQqwxWAfeMnGCnRDUb9sR2sCBq/9DwIY\r\nP+/4vCRvhGCEFY0B7crpn/QpeT7h+A7wtabX4jNPINV9RZlWZt9PBo8auiesztEn\r\ngEPBQ4ITMfuwCpksTuB81iD+08Y9kR8eyTZInDyMnL4QAkgHHzVbE7a5kaBks+0o\r\nI/hS5AQZHxmDLh43qv70R93bfnUFFNijcAng2sGiCdkGAu5HgaUOGTdp0/dJTS8/\r\nLAnwQNh5cD5PwhG4gHLphEtoAAryImYrD4xZ9abjXYHj3iXD3p3Cyd7xtWm7nQKK\r\nbEVEd4E9AgMBAAECggEAASQJglUf8Fm/zlgdaEmnrMUNMUTigLycfCKPXBrPC38/\r\nF6cYNvaV2VdP0y5//9fbCgmIvkU/QVLn1h5BikyvvSbd9PhvMnYD7ZG1DHxF00pV\r\nnUsUuDeFG3HH30v48s3Id4D9LCsbBSY+IPG+v/1xUyhSK5VxQwZBUctSYQGaLQzQ\r\nMhewpk0bJ5VaocqDtrb9z2TizJX4fy3E4YH83Pv/DvFPySeAKTGw1v+YXAqxkHFw\r\nVeUmsbxQJ4szH45WHeXLWLR73gPKNfbVMP4t87Lpd0rTLVt9yfohB93a6DDgYbnP\r\nwUHiaejGLwX1HmdSqPeq90Z3rmUYbYMkjRsjr660lwKBgQDm/T+7kFnZO31jVAka\r\nKgf/OGWoX6jsOIDSC36OLiKxhkK79W9Ps+vf8qyoO8YPVQWwM104jcZC47PS27h+\r\nsReMoV2bJB1+xYFIJghC4zIpDcZ08bW0Ns6xGJsAoUkinKZ9zhOHmtu30FSa1opL\r\nDucbstLyNFY+qWFJk5uatQij1wKBgQDwmRWTY2noBM/1/RVV9z1upnsDnYdv6bY4\r\nh/wArD0PaRxSRoqlgcefZrrMbJXy7wu3C7rWhlgzYITMFJw65bxcfINjqyyE5cGk\r\ndOM707kZIcRUakEI9kQbEPJspv+X7mgoSOAwtt9FQgYblYPc8JXfEYAxxxeWc0xx\r\n1QDroJxhCwKBgE6j2ZbZxj0W69FtQswNkztoz/NK3g/ODM117FgrjNQziXTEUmko\r\nMB3GWNHNx9hgcddTJWGjouQS8Z3QADfhwsq2BVBUM1Z9l04g5J8hCmq/rdkSkXIR\r\nVr0kS2Ejh+qoumYKSsvYBQXHf4ZXlC2JnVToxLiA6PvcXqrV/hvlllNxAoGBALK9\r\nF2FCdpgukwws8x/FKDc+qJ6b9dT3LC89HsKlMktzi923mCKykkliOR3LAW7TlcFr\r\njmb2sSmh56XxHctHhrKysa1mqhEk2sHBMFruxFDeXAtWUHBG+3ucEG0Vd0Y4j9p1\r\noU+vW5kJHp55adfGR6DLUJAqVuSnTUA3vJJP5DzXAoGBAMBCQ6Ps8QMlZ6NiFFvr\r\n/5AzzF1SC6JA5NN+9GUsY7ME8ZFXUkY9ZcXkC3a2agel6y6ES5m+wkBGUooTG9br\r\ncj8E2tk8ilYsZdtvQ82Dn+y512SWxMm5TJk58A5kEohz/b8n44j/n9v1B4lFU4zd\r\ndJ8Dt1z3G9DRyQgKGJCSKgmN\r\n-----END PRIVATE KEY-----\r\n`
    const crtPem = req.body.crtPem
    const privateKeyPem = req.body.privateKeyPem
    
    try{
        if(!crtPem || !privateKeyPem){
            return res.status(400).json({
                status: false,
                message: 'privateKeyPem and crtPem are required.'
            })
        }
        if (!isValidSslCertString(crtPem,'crt')) {
            return res.status(400).json({
                status: false,
                message: 'crtPem is not valid.'
            })
        }
        if (!isValidSslCertString(privateKeyPem,'privateKey')) {
            return res.status(400).json({
                status: false,
                message: 'privateKeyPem is not valid.'
            })
        }

        const crt = forge.pki.certificateFromPem(crtPem);
        const privateKey = forge.pki.privateKeyFromPem(privateKeyPem);

        const crtPublicKeyOid = crt.publicKey.n.toString(10);
        const privateKeyPublicKeyOid = privateKey.n.toString(10);

        if (crtPublicKeyOid === privateKeyPublicKeyOid) {
            return res.status(200).json({
                status: true,
                message: 'The codes between CRT and private key match.'
            })
        } else {
            return res.status(400).json({
                status: false,
                message: 'The codes between CRT and private key do not match.'
            })
        }
    }catch(err){
        return res.status(500).json({
            status: false,
            message: "Internal Server Error"
        })
    }
}

// Kiểm tra thông tin SSL đã cài đặt
const sslInfoCheck = async (req, res) => {
    const domain = req.query.domain?.replace(/^https?:\/\//, '');
    const port = '443';
    try{
        if(!domain){
            return res.status(400).json({
                status: false,
                message: "Domain is required."
            })
        }
        if(!isValidDomain(domain)){
            return res.status(400).json({
                status: false,
                message: "Domain is not valid."
            })
        }
        const serverIPAddress = await checkIpAddresses(domain)
        if(!serverIPAddress){
            return res.status(400).json({
                status: false,
                message: `Could not find information about ${domain}`
            })
        }
        // Dùng thêm catch ở đây để phòng trường hợp trang web chặn req
        let serverType = ''
        await axios.head(`http://${domain}`)
            .then(response => {
                serverType = response.headers['server']
            })
            .catch(error => {})

        exec(`openssl s_client -showcerts -connect ${domain}:${port} </dev/null`, async (error, stdout, stderr) => {
            if (error) {
                return res.status(500).json({ 
                    status: false,
                    message: "Internal Server Error"
                });
            }
            const regex = /-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----/gs;
            const match = [...stdout.matchAll(regex)].map(match => match[0])

            let cert = '';
            let errorHandled = false;
            await axios.post(process.env.CRT_URL, {sslCrt: match.shift()})
                .then(response => {
                    cert = response.data.data
                })
                .catch(err => {
                    // Không return ở đây vì bên dưới còn cái return nữa
                    // set lại header sau khi gửi sẽ lỗi
                    console.log(err.message)
                    errorHandled = true;
                })
            if(errorHandled){
                return res.status(400).json({ 
                    status: false,
                    message: "The certificate key algorithm is not supported"
                });
            }

            let chains = []
            for(let chain of match){
                const item = forge.pki.certificateFromPem(chain);
                const commonName = item.subject.getField('CN') ? item.subject.getField('CN').value : '';
                const organizationName = item.subject.getField('O') ? item.subject.getField('O').value : '';
                const localityName = item.subject.getField('L') ? item.subject.getField('L').value : '';
                const serialNumber = item.serialNumber;
                const signatureAlgorithmValue = item.signatureOid;
                const issuerName = item.issuer.getField('CN') ? item.issuer.getField('CN').value : '';
                const startDate = item.validity.notBefore;
                const endDate = item.validity.notAfter;

                const crtInfo = {
                    commonName,
                    organizationName,
                    localityName,
                    serialNumber,
                    signatureAlgorithmValue,
                    issuerName,
                    startDate,
                    endDate,
                };
                chains.push(crtInfo)
            }

            return res.status(200).json({
                status: true,
                message: 'Check installed SSL information successfully.',
                data: {
                    serverIPAddress, 
                    serverType,
                    ...cert,
                    chains
                }
            });
        });
    }catch(err){
        return res.status(500).json({
            status: false,
            message: "Internal Server Error"
        })
    }
};

const convertPEMtoDER = (req,res) => {
    const filePath = req.file?.path
    const derFilePath = 'converted-file.der';
    const command = `openssl x509 -outform der -in ${filePath} -out ${derFilePath}`;
    try {
        if (!filePath) {
            return res.status(400).send({
                status: false,
                message: 'Pem file is required',
            });
        }
        exec(command, (error, stdout, stderr) => {
            if (error) {
                return res.status(500).json({status: false, message: 'Failed to convert file.' });
            }
            res.download(derFilePath, derFilePath, (err) => {
                if (err) {
                    return res.status(500).send({
                        status: false,
                        message: 'An error occurred while sending the file',
                    });
                }
                fs.unlinkSync(derFilePath);
            }); 
        });
    } catch (err) {
        res.status(500).send({
            status: false,
            message: 'An error occurred while converting the file',
        });
    }
}

const convertPEMtoPFX = (req, res) => {
    if (!req.files['certificate'] || !req.files['privateKey'] || !req.files['caBundle']) {
        return res.status(400).send({
            status: false,
            message: 'Certificate, Private Key, and CA Bundle files are required',
        });
    }
    const certFilePath = req.files['certificate'][0].path;
    const privateKeyFilePath = req.files['privateKey'][0].path;
    const caBundleFilePath = req.files['caBundle'].map(file => file.path).join(' ');
    const pfxFilePath = 'converted-file.pfx';
    const password = req.body.password;
    if (!password) {
        return res.status(400).send({
            status: false,
            message: 'Password is required',
        });
    }
    const command = `openssl pkcs12 -export -out ${pfxFilePath} -inkey ${privateKeyFilePath} -in ${certFilePath} -certfile ${caBundleFilePath} -passout pass:${password}`;
    try{
        exec(command, (error, stdout, stderr) => {
            if (error) {
                return res.status(500).json({ status: false, message: 'Failed to convert file.', error: error.message });
            }
            res.download(pfxFilePath, pfxFilePath, (err) => {
               if (err) {
                    return res.status(500).send({
                        status: false,
                        message: 'An error occurred while sending the file',
                    });
                }
                fs.unlinkSync(pfxFilePath);
            }); 
        });
    }catch (err) {
        res.status(500).send({
            status: false,
            message: 'An error occurred while converting the file',
        });
    }
}

const convertPEMtoP7B = (req, res) => {
    if (!req.files['certificate'] || !req.files['caBundle']) {
        return res.status(400).send({
            status: false,
            message: 'Certificate, CA Bundle files are required',
        });
    }
    const certFilePath = req.files['certificate'][0].path;
    const caBundleFilePath = req.files['caBundle'].map(file => file.path).join(' ');
    const p7bFilePath = 'converted-file.p7b';
    const command = `openssl crl2pkcs7 -nocrl -certfile ${certFilePath} -out ${p7bFilePath} -certfile ${caBundleFilePath}`;
    try{
        exec(command, (error, stdout, stderr) => {
            if (error) {
                return res.status(500).json({ status: false, message: 'Failed to convert file.' });
            }
            res.download(p7bFilePath, p7bFilePath, (err) => {
                if (err) {
                    return res.status(500).send({
                        status: false,
                        message: 'An error occurred while sending the file',
                    });
                }
                fs.unlinkSync(p7bFilePath);
            });
        });
    }catch(err){
        res.status(500).send({
            status: false,
            message: 'An error occurred while converting the file',
        });
    }
}

const convertDERtoPEM = (req, res) => {
    const filePath = req.file?.path
    const pemFilePath = 'converted-file.pem';
    const command = `openssl x509 -inform der -in ${filePath} -out ${pemFilePath}`;
    try{
        if (!filePath) {
            return res.status(400).send({
                status: false,
                message: 'Pem file is required',
            });
        }
        exec(command, (error, stdout, stderr) => {
            if (error) {
                return res.status(500).json({status: false, message: 'Failed to convert file.' });
            }
            res.download(pemFilePath, pemFilePath, (err) => {
                if (err) {
                    return res.status(500).send({
                        status: false,
                        message: 'An error occurred while sending the file',
                    });
                }
                fs.unlinkSync(pemFilePath);
            });
        });
    }catch (err) {
        res.status(500).send({
            status: false,
            message: 'An error occurred while converting the file',
        });
    }
}

const convertPFXtoPEM = (req, res) => {
    const pfxFilePath = req.file?.path
    const password = req.body.password
    const pemFilePath = 'converted-file.pem';
    const command = `openssl pkcs12 -in ${pfxFilePath} -out ${pemFilePath} -nodes -password pass:${password}`;
    try{
        if (!pfxFilePath) {
            return res.status(400).send({
                status: false,
                message: 'PFX file is required',
            });
        }
        if (!password) {
            return res.status(400).send({
                status: false,
                message: 'Password is required',
            });
        }
        exec(command, (error, stdout, stderr) => {
            if (error) {
                return res.status(500).json({status: false, message: 'Failed to convert file.' });
            }
            res.download(pemFilePath, pemFilePath, (err) => {
                if (err) {
                    return res.status(500).send({
                        status: false,
                        message: 'An error occurred while sending the file',
                    });
                }
                fs.unlinkSync(pemFilePath);
            })
        })
    }catch(err){
        res.status(500).send({
            status: false,
            message: 'An error occurred while converting the file',
        });
    }
}

const convertP7BtoPEM = (req, res) => {
    const p7bFilePath = req.file?.path
    const pemFilePath = 'converted-file.pem';
    const command = `openssl pkcs7 -print_certs -in ${p7bFilePath} -out ${pemFilePath}`;
    try{
        if (!p7bFilePath) {
            return res.status(400).send({
                status: false,
                message: 'P7B file is required',
            });
        }
        exec(command, (error, stdout, stderr) => {
            if (error) {
                return res.status(500).json({status: false, message: 'Failed to convert file.' });
            }
            res.download(pemFilePath, pemFilePath, (err) => {
                if (err) {
                    return res.status(500).send({
                        status: false,
                        message: 'An error occurred while sending the file',
                    });
                }
                fs.unlinkSync(pemFilePath);
            });
        })
    }catch(err){
        res.status(500).send({
            status: false,
            message: 'An error occurred while converting the file',
        });
    }
}

const convertP7BtoPFX = (req, res) => {
    if (!req.files['p7b'] || !req.files['privateKey'] || !req.files['caBundle']) {
        return res.status(400).send({
            status: false,
            message: 'P7B, Private Key, and CA Bundle files are required',
        });
    }
    const p7bFilePath = req.files['p7b'][0].path;
    const privateKeyFilePath = req.files['privateKey'][0].path;
    const caBundleFilePath = req.files['caBundle'].map(file => file.path).join(' ');
    const pfxFilePath = 'converted-file.pfx';
    const password = req.body.password;
    if (!password) {
        return res.status(400).send({
            status: false,
            message: 'Password is required',
        });
    }
    const command = `openssl pkcs7 -print_certs -in ${p7bFilePath} -out intermediate.pem && \
        openssl pkcs12 -export -out ${pfxFilePath} -inkey ${privateKeyFilePath} \
        -in intermediate.pem -certfile ${caBundleFilePath} -passout pass:${password}`;
    try{
        exec(command, (error, stdout, stderr) => {
            if (error) {
                return res.status(500).send({
                    status: false,
                    message: 'An error occurred while converting the file',
                });
            }
            // Send the PFX file as a response
            res.download(pfxFilePath, pfxFilePath, (err) => {
                if (err) {
                    return res.status(500).send({
                        status: false,
                        message: 'An error occurred while sending the file',
                    });
                }
                fs.unlinkSync('intermediate.pem');
                fs.unlinkSync(pfxFilePath);
            });
        });
    }catch(err){
        res.status(500).send({
            status: false,
            message: 'An error occurred while converting the file',
        });
    }
} 

const CAAGenerator = (req, res) => {
    const domain = req.query.domain?.replace(/^https?:\/\//, '');
    const supplier = req.query.supplier
    const wildcard = req.query.wildcard
    if(!domain || !isValidDomain(domain)){
        return res.status(400).json({
            status: false,
            message: "Invalid domain"
        })
    }
    if(!supplier || !VALID_SUPPLIER.includes(supplier)){
        return res.status(400).json({
            status: false,
            message: "Invalid supplier"
        })
    }
    if(!wildcard || !VALID_WILDCARD.includes(wildcard)){
        return res.status(400).json({
            status: false,
            message: "Invalid wildcard"
        })
    }
    const data = {
        id: `caa-record-sectigo-${wildcard}`,
        data: []
    }
    try{
        const issue = `issue${wildcard === 'wildcard' ? 'wild' : ''}`
        // Bind zone file
        const bind = {
            title: 'Standard BIND Zone File',
            content: [
                `${domain}. IN CAA 0 ${issue} "${supplier}"`,
            ]
        }
        data.data.push(bind)
        const hexHead = '000' + issue.length;
        const asciiValue = `${issue}${supplier}`;
        const hexValue = hexHead + Buffer.from(asciiValue, 'ascii').toString('hex').toUpperCase();
        const byteLength = hexValue.length / 2
        const legacy = {
            title: "Legacy Zone File",
            content: [
                `${domain}. IN TYPE257 \\# ${byteLength} ${hexValue}`
            ]
        }
        data.data.push(legacy)
        function asciiToOctal(asciiString) {
            let octalString = '';
            for (let i = 0; i < asciiString.length; i++) {
                const charCode = asciiString.charCodeAt(i);
                octalString += '\\' + charCode.toString(8).padStart(3, '0');
            }
            return octalString;
        }
        const octalString = asciiToOctal(asciiValue);
        const tinydns = {
            title: 'tinydns',
            content: [
                `:${domain}:257:\\000${wildcard !== 'wildcard' ? '\\005' : '\\011'}${octalString}`
            ]
        }
        data.data.push(tinydns)
        return res.status(200).json({
            status: true,
            message: `CAA record - Domain: ${domain}`,
            data
        })
    }catch(err){
        return res.status(500).json({
            status: false,
            message: "Internal Server Error"
        })
    }
}

module.exports = {
    csrGenerator,
    csrDecode,
    sslCrtDecode,
    checkSSL,
    sslCheckMatchCSR,
    sslCheckMatchKey,
    sslInfoCheck,
    convertPEMtoDER,
    convertPEMtoPFX,
    convertPEMtoP7B,
    convertDERtoPEM,
    convertPFXtoPEM,
    convertP7BtoPEM,
    convertP7BtoPFX,
    CAAGenerator
}
