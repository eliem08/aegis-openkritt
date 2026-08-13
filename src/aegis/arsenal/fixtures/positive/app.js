const child = require("child_process");
function unsafe(input) { return child.exec(input); }
module.exports = { unsafe };
