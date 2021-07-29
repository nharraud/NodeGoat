const ProfileDAO = require("../data/profile-dao").ProfileDAO;
const ESAPI = require('node-esapi')
const {
    environmentalScripts
} = require("../../config/config");

/* The ProfileHandler must be constructed with a connected db */
function ProfileHandler(db) {
    "use strict";

    const profile = new ProfileDAO(db);

    this.displayProfile = (req, res, next) => {
        const {
            userId
        } = req.session;



        profile.getByUserId(parseInt(userId), (err, doc) => {
            if (err) return next(err);
            doc.userId = userId;

            // @TODO @FIXME
            // while the developer intentions were correct in encoding the user supplied input so it
            // doesn't end up as an XSS attack, the context is incorrect as it is encoding the website for HTML
            // doc.website = ESAPI.encoder().encodeForHTML(doc.website)
            // fix it by replacing the above with another template variable that is used for 
            // the context of a URL in a link header
            this.sanitizeProfile(doc);
            return res.render("profile", {
                ...doc,
                environmentalScripts
            });
        });
    };

    this.sanitizeProfile = (profile) => {
        // Note: OWASP example seems to have been broken in the following commit
        // https://github.com/OWASP/NodeGoat/commit/7c293e721bd1e95be6f82475d295b9b10e3b584e
        profile.website = ESAPI.encoder().encodeForHTMLAttribute(profile.website);
        profile.firstNameSafeString = ESAPI.encoder().encodeForHTML(profile.firstName);
        profile.firstNameSafeURLString = ESAPI.encoder().encodeForURL(profile.firstName);
    };

    this.handleProfileUpdate = (req, res, next) => {

        const {
            firstName,
            lastName,
            ssn,
            dob,
            address,
            bankAcc,
            bankRouting,
            website
        } = req.body;

        // Fix for Section: ReDoS attack
        // The following regexPattern that is used to validate the bankRouting number is insecure and vulnerable to
        // catastrophic backtracking which means that specific type of input may cause it to consume all CPU resources
        // with an exponential time until it completes
        // --
        // The Fix: Instead of using greedy quantifiers the same regex will work if we omit the second quantifier +
        // const regexPattern = /([0-9]+)\#/;
        const regexPattern = /([0-9]+)+\#/;
        // Allow only numbers with a suffix of the letter #, for example: 'XXXXXX#'
        const testComplyWithRequirements = regexPattern.test(bankRouting);
        // if the regex test fails we do not allow saving
        if (testComplyWithRequirements !== true) {
            const profile = {
                updateError: "Bank Routing number does not comply with requirements for format specified",
                firstName,
                lastName,
                ssn,
                dob,
                address,
                bankAcc,
                bankRouting,
                environmentalScripts,
                website,
            }
            this.sanitizeProfile(profile)
            return res.render("profile", profile);
        }

        const {
            userId
        } = req.session;

        profile.updateUser(
            parseInt(userId),
            firstName,
            lastName,
            ssn,
            dob,
            address,
            bankAcc,
            bankRouting,
            website,
            (err, user) => {

                if (err) return next(err);

                // WARN: Applying any sting specific methods here w/o checking type of inputs could lead to DoS by HPP
                //firstName = firstName.trim();
                user.updateSuccess = true;
                user.userId = userId;
                this.sanitizeProfile(user);

                return res.render("profile", {
                    ...user,
                    environmentalScripts
                });
            }
        );

    };

}

module.exports = ProfileHandler;
