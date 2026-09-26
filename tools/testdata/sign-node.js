const crypto = require('crypto');

function generateSignature(httpMethod, urlPath, salt, timestamp, accessKey, secretKey, body) {
    try {
        let bodyString = "";
        if (body) {
            bodyString = JSON.stringify(body);      
            bodyString = bodyString == "{}" ? "" : bodyString; // If body was empty, the body string should also be empty (and not curly braces)
        }
        
        let toSign = httpMethod.toLowerCase() + urlPath + salt + timestamp + accessKey + secretKey + bodyString;

        let hash = crypto.createHmac('sha256', secretKey);
        hash.update(toSign);
        
        const signature = Buffer.from(hash.digest("hex")).toString("base64")

        return signature;
    } catch (error) {
        console.error("An error occurred when generating the signature");
        throw error;
    }
}
