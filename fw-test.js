const fs = require('fs');
const csv = require('csv-parser');
const { Parser } = require('json2csv');
const path = require('path');

// File paths
const inputFilePath = path.join(__dirname, 'test-dataset.csv'); // Adjust path as needed
const reportFilePath = path.join(__dirname, 'threat-report.csv'); // New report file

// Define allowlist and blocklist
let allowlist = new Set();
let blocklist = new Map();

// Threat patterns categorized by severity
const patterns = {
    // High Severity - Immediate Block
    xss: { pattern: /<script|<\/script|javascript:/i, severity: 'High' },
    sqli: { pattern: /'|--|union|select|insert|drop|update/i, severity: 'High' },
    dos: { pattern: /(?:[0-9]{1,3}\.){3}[0-9]{1,3}.*?(GET|POST|HEAD)/i, severity: 'High' },
    ddos: { pattern: /(?:[0-9]{1,3}\.){3}[0-9]{1,3}.+?(GET|POST|HEAD)/i, severity: 'High' },
    ssrf: { pattern: /\/api\/proxy\/[a-zA-Z0-9]+/i, severity: 'High' },

    // Medium Severity - Flag and Temporarily Block
    pathTraversal: { pattern: /\.\.\//i, severity: 'Medium' },
    brokenObjectLevelAuthorization: { pattern: /\/api\/v1\/objects\/[0-9]+\/(details|edit)/i, severity: 'Medium' },
    brokenAuthentication: { pattern: /Authorization: Bearer [a-zA-Z0-9]+/i, severity: 'Medium' },

    // Low Severity - Flag Only
    securityMisconfiguration: { pattern: /\/config\/[a-zA-Z0-9]+/i, severity: 'Low' },
    improperInventoryManagement: { pattern: /\/api\/inventory\/[a-zA-Z0-9]+\/details/i, severity: 'Low' },
    unsafeConsumptionOfAPIs: { pattern: /\/api\/consume\/[a-zA-Z0-9]+/i, severity: 'Low' }
};

// Track actions and reports
const actionLog = [];
const report = [];

// Load allowlist and blocklist
const loadLists = () => {
    // Example allowlist IPs
    allowlist.add('192.168.1.100'); // Example IP that is always allowed
    // Example blocklist IPs with timestamp for temporary blocks
    blocklist.set('192.168.1.200', Date.now()); // Example IP blocked initially
};

// Function to check if traffic should be blocked, allowed, or flagged
const checkTraffic = (traffic) => {
    const { ClientIP, ClientRequestURI } = traffic;

    // Check blocklist
    if (blocklist.has(ClientIP)) {
        const blockTime = blocklist.get(ClientIP);
        if (Date.now() - blockTime < 12 * 60 * 60 * 1000) { // 12 hours
            actionLog.push({ action: 'BLOCKED', ip: ClientIP, reason: 'Blocklist' });
            report.push({ IP: ClientIP, Action: 'Blocked', Reason: 'Blocklist' });
            return 'Blocked';
        } else {
            blocklist.delete(ClientIP); // Remove expired IP from blocklist
        }
    }

    // Check allowlist
    if (allowlist.has(ClientIP)) {
        actionLog.push({ action: 'ALLOWED', ip: ClientIP, reason: 'Allowlist' });
        report.push({ IP: ClientIP, Action: 'Allowed', Reason: 'Allowlist' });
        return 'Allowed';
    }

    // Check for threats
    for (const [key, { pattern, severity }] of Object.entries(patterns)) {
        if (pattern.test(ClientRequestURI)) {
            if (severity === 'High') {
                actionLog.push({ action: 'BLOCKED', ip: ClientIP, reason: key });
                blocklist.set(ClientIP, Date.now()); // Block IP after flagging
                report.push({ IP: ClientIP, Action: 'Blocked', Reason: key });
                return 'Blocked';
            } else if (severity === 'Medium') {
                actionLog.push({ action: 'FLAGGED AND BLOCKED', ip: ClientIP, reason: key });
                blocklist.set(ClientIP, Date.now()); // Temporarily block IP
                report.push({ IP: ClientIP, Action: 'Flagged and Blocked', Reason: key });
                return 'Flagged and Blocked';
            } else if (severity === 'Low') {
                actionLog.push({ action: 'FLAGGED', ip: ClientIP, reason: key });
                report.push({ IP: ClientIP, Action: 'Flagged', Reason: key });
                return 'Flagged';
            }
        }
    }

    // Default action
    actionLog.push({ action: 'ALLOWED', ip: ClientIP, reason: 'Default' });
    report.push({ IP: ClientIP, Action: 'Allowed', Reason: 'Default' });
    return 'Allowed';
};

// Function to write data to a single CSV report file
const writeToCSV = (filePath, data, description) => {
    try {
        const json2csvParser = new Parser();
        const csv = json2csvParser.parse(data);
        fs.writeFileSync(filePath, csv);
        console.log(`${description} successfully saved to ${filePath}`);
    } catch (err) {
        console.error(`Failed to save ${description} to ${filePath}:`, err.message);
    }
};

// Process CSV file
const processCSV = (filePath) => {
    loadLists(); // Load allowlist and blocklist

    fs.createReadStream(filePath)
        .pipe(csv())
        .on('data', (row) => {
            checkTraffic(row);
        })
        .on('end', () => {
            console.log('CSV file successfully processed.');
            console.log('Action Log:', actionLog);

            // Write the single report to a CSV file
            writeToCSV(reportFilePath, report, 'Threat report');

            console.log('Reports generation completed.');
        })
        .on('error', (err) => {
            console.error('Error processing CSV file:', err.message);
        });
};

// Usage
processCSV(inputFilePath);
