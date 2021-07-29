/* The ProfileDAO must be constructed with a connected database object */
function ProfileDAO(db) {

    "use strict";

    /* If this constructor is called without the "new" operator, "this" points
     * to the global object. Log a warning and call it correctly. */
    if (false === (this instanceof ProfileDAO)) {
        console.log("Warning: ProfileDAO constructor called without 'new' operator");
        return new ProfileDAO(db);
    }

    const users = db.collection("users");

    /* Fix for A6 - Sensitive Data Exposure */

    // Use crypto module to save sensitive data such as ssn, dob in encrypted format
    const crypto = require("crypto");
    const config = require("../../config/config");

    /// Helper method create initialization vector
    // By default the initialization vector is not secure enough, so we create our own
    const createIV = () => crypto.randomBytes(16);
    const createSalt = () => crypto.randomBytes(16);
    const deriveKey = (salt) => {
        return crypto.pbkdf2Sync(config.cryptoKey, salt, 100000, 32, "sha512");
    };

    // Note the encryption version from NodeGoat is buggy as the IV is too long and the password is not derived as recommended.
    // See https://github.com/nodejs/node/blob/933d8eb689bb4bc412e71c0069bf9b7b24de4f9d/doc/api/deprecations.md#dep0106-cryptocreatecipher-and-cryptocreatedecipher
    // Helper methods to encryt / decrypt
    const encrypt = (toEncrypt) => {
        const iv = createIV();
        const salt = createSalt();
        const derivedKey = deriveKey(salt);
        const cipher = crypto.createCipheriv(config.cryptoAlgo, derivedKey, iv);
        const encrypted = Buffer.concat([cipher.update(toEncrypt), cipher.final()]);
        return `${salt.toString('hex')}:${iv.toString('hex')}:${encrypted.toString('hex')}`;
    };

    const decrypt = (toDecrypt) => {
        const [saltHex, ivHex, encryptedHex] = toDecrypt.split(':');
        const salt = Buffer.from(saltHex, 'hex');
        const iv = Buffer.from(ivHex, 'hex');
        const encrypted = Buffer.from(encryptedHex, 'hex');
        const derivedKey = deriveKey(salt);
        const decipher = crypto.createDecipheriv(config.cryptoAlgo, derivedKey, iv);
        return `${decipher.update(encrypted)}${decipher.final()}`;
    };

    this.updateUser = (userId, firstName, lastName, ssn, dob, address, bankAcc, bankRouting, website, callback) => {

        // Create user document
        const user = {};
        if (firstName) {
            user.firstName = firstName;
        }
        if (lastName) {
            user.lastName = lastName;
        }
        if (address) {
            user.address = address;
        }
        if (bankAcc) {
            user.bankAcc = bankAcc;
        }
        if (bankRouting) {
            user.bankRouting = bankRouting;
        }
        if (website) {
            user.website = website;
        }

        // Fix for A6 - Sensitive Data Exposure
        // Store encrypted ssn and DOB
        if(ssn) {
            user.ssn = encrypt(ssn);
        }
        if(dob) {
            user.dob = encrypt(dob);
        }

        users.update({
                _id: parseInt(userId)
            }, {
                $set: user
            },
            err => {
                if (!err) {
                    console.log("Updated user profile");
                    return callback(null, {...user, ssn, dob});
                }

                return callback(err, null);
            }
        );
    };

    this.getByUserId = (userId, callback) => {
        users.findOne({
                _id: parseInt(userId)
            },
            (err, user) => {
                if (err) return callback(err, null);
                // Fix for A6 - Sensitive Data Exposure
                // Decrypt ssn and DOB values to display to user
                user.ssn = user.ssn ? decrypt(user.ssn) : "";
                user.dob = user.dob ? decrypt(user.dob) : "";

                callback(null, user);
            }
        );
    };
}

module.exports = { ProfileDAO };
