'use strict';
var moment = require('moment');
var CryptoJS = require("crypto-js");
const { v4: uuid } = require('uuid');

const fs = require('fs');

var params = process.argv.slice(2);
var inputFile = params[0]
var tool = params[1]

var inicio = moment().format('YYYY-MM-DDTHH:mm:ss.SSSSSSZ')
var uuidAnalisis = uuid()
var vulnerabilities = []

let rawdata = fs.readFileSync(inputFile);

if (tool === 'nodejsscan') {
    let nodejsscan = JSON.parse(rawdata);

    let issues = nodejsscan.nodejs 

    for (var clave in issues) {
        if (issues.hasOwnProperty(clave)) {

            for (var i in issues[clave].files) {

                var vulnerabilitie = {
                    "vulnerabilityID": "00000000-0000-0000-0000-000000000000",
                    "analysisID": uuidAnalisis,
                    "createdAt": moment().format('YYYY-MM-DDTHH:mm:ss.SSSSSSZ'),
                    "vulnerabilities": {
                    "vulnerabilityID": uuid(),
                    "line": issues[clave].files[i].match_lines[0],
                    "column": issues[clave].files[i].match_position[0],
                    "confidence": "MEDIUM",
                    "file": issues[clave].files[i].file_path,
                    "code": "",
                    "details": issues[clave].metadata.cwe + " - " + issues[clave].metadata.description + " - " + issues[clave].metadata.owasp,
                    "securityTool": "NodejsScan",
                    "language": "NodeJS",
                    "severity": issues[clave].metadata.severity,
                    "type": "Vulnerability",
                    "commitAuthor": "-",
                    "commitEmail": "-",
                    "commitHash": "-",
                    "commitMessage": "-",
                    "commitDate": "-",
                    "vulnHash": CryptoJS.SHA256(issues[clave].files[i].match_string).toString()
                    }
                }
                
                vulnerabilities.push(vulnerabilitie)
            }
        }
    }
} else if (tool === 'checkov') {
    let checkov = JSON.parse(rawdata);

//    console.log(checkov)

    for (var item of checkov) {
//        console.log(item.results.failed_checks)

        if (item.results.failed_checks.length > 0) {
//            console.log(item.results.failed_checks)

            for (var failed of item.results.failed_checks) {
                var vulnerabilitie = {
                    "vulnerabilityID": "00000000-0000-0000-0000-000000000000",
                    "analysisID": uuidAnalisis,
                    "createdAt": moment().format('YYYY-MM-DDTHH:mm:ss.SSSSSSZ'),
                    "vulnerabilities": {
                    "vulnerabilityID": uuid(),
                    "line": failed.file_line_range[0],
                    "column": failed.file_line_range[1],
                    "confidence": "MEDIUM",
                    "file": failed.repo_file_path,
                    "code": "",
                    "details": failed.check_name + " - Resource: " + failed.resource + " - More info: " + failed.guideline,
                    "securityTool": "Checkov",
                    "language": item.check_type,
                    "severity": failed.check_result.result,
                    "type": "Vulnerability",
                    "commitAuthor": "-",
                    "commitEmail": "-",
                    "commitHash": "-",
                    "commitMessage": "-",
                    "commitDate": "-",
                    "vulnHash": CryptoJS.SHA256(failed.bc_check_id + failed.check_class).toString()
                    }
                }
                
                vulnerabilities.push(vulnerabilitie)
            }
            
        }
    }
}



var final = moment().format('YYYY-MM-DDTHH:mm:ss.SSSSSSZ')

var resultado = {
    "version": "v2.6.4",
    "id": uuidAnalisis,
    "repositoryID": "00000000-0000-0000-0000-000000000000",
    "repositoryName": "",
    "workspaceID": "00000000-0000-0000-0000-000000000000",
    "workspaceName": "",
    "status": "success",
    "errors": "",
    "createdAt": inicio,
    "finishedAt": final,
    "analysisVulnerabilities": vulnerabilities
}

console.log(resultado)

fs.writeFileSync('output_formated.json', JSON.stringify(resultado, null, 2));