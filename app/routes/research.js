const ResearchDAO = require("../data/research-dao").ResearchDAO;
const needle = require("needle");
const {
    environmentalScripts
} = require("../../config/config");

const symbolPattern = /^[0-9a-zA-Z]+$/;

function ResearchHandler(db) {
    "use strict";

    const researchDAO = new ResearchDAO(db);

    this.displayResearch = (req, res) => {
        if (req.query.symbol) {
            if (symbolPattern.test(req.query.symbol) !== true) {
                res.status(400)
                res.send({ error: 'Invalid Symbol' });
                return res.end();
            }

            const url = 'https://finance.yahoo.com/quote/' + req.query.symbol;
            return needle.get(url, (error, newResponse, body) => {
                if (!error && newResponse.statusCode === 200) {
                    res.writeHead(200, {
                        "Content-Type": "text/html"
                    });
                }
                res.write("<h1>The following is the stock information you requested.</h1>\n\n");
                res.write("\n\n");
                if (body) {
                    res.write(body);
                }
                return res.end();
            });
        }

        return res.render("research", {
            environmentalScripts
        });
    };

}

module.exports = ResearchHandler;
