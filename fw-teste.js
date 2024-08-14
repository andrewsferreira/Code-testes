const fs = require('fs'); // Necessário para trabalhar com arquivos em JavaScript
const Papa = require('papaparse'); // Necessário para realizar uma leitura em alto nível do .csv carregado
const { Parser } = require('json2csv'); // Necessário para fazer a conversão e geração de reports .csv
const path = require('path'); // Necessário para validar o 'path' de caminho de diretório

// Diretório de arquivos
const inputFilePath = path.join(__dirname, 'test-dataset.csv'); // Coloque o nome do CSV que irá carregar, necessário estar o .csv na mesma pasta do script
const blockedFilePath = path.join(__dirname, 'blocked-ips.csv');
const flaggedFilePath = path.join(__dirname, 'flagged-ips.csv');
const allowedFilePath = path.join(__dirname, 'allowed-ips.csv');
const attackAttemptsFilePath = path.join(__dirname, 'attack-attempts.csv');

// Define Lista de Permissão e de Bloqueio
let allowlist = new Set();
let blocklist = new Map();
let accessLog = new Map(); // Para rastrear tentativas de acesso em um curto espaço de tempo

// Ameaças categorizadas por severidade
const patterns = {
    // Severidade Alta - Bloqueio Imediato
    xss: { pattern: /<script|<\/script|javascript:/i, severity: 'High' },
    sqli: { pattern: /'|--|union|select|insert|drop|update/i, severity: 'High' },
    dos: { pattern: /(?:[0-9]{1,3}\.){3}[0-9]{1,3}.*?(GET|POST|HEAD)/i, severity: 'High' },
    ddos: { pattern: /(?:[0-9]{1,3}\.){3}[0-9]{1,3}.+?(GET|POST|HEAD)/i, severity: 'High' },
    ssrf: { pattern: /\/api\/proxy\/[a-zA-Z0-9]+/i, severity: 'High' },

    // Severidade média - Flag e Bloqueio Temporário
    pathTraversal: { pattern: /\.\.\//i, severity: 'Medium' },
    brokenObjectLevelAuthorization: { pattern: /\/api\/v1\/objects\/[0-9]+\/(details|edit)/i, severity: 'Medium' },
    brokenAuthentication: { pattern: /Authorization: Bearer [a-zA-Z0-9]+/i, severity: 'Medium' },

    // Severidade Baixa - Apenas Flag
    securityMisconfiguration: { pattern: /\/config\/[a-zA-Z0-9]+/i, severity: 'Low' },
    improperInventoryManagement: { pattern: /\/api\/inventory\/[a-zA-Z0-9]+\/details/i, severity: 'Low' },
    unsafeConsumptionOfAPIs: { pattern: /\/api\/consume\/[a-zA-Z0-9]+/i, severity: 'Low' }
};

// Para tomada de decisão e geração de relatório
const blockedIPs = [];
const flaggedIPs = [];
const allowedIPs = [];
const attackAttempts = [];

// Lendo Lista de Permissão e de Bloqueio
const loadLists = () => {
    // Exemplo de IP na lista de permissão
    allowlist.add('192.168.1.100'); // Exemplo de IP na lista de permissão
    // Exemplo de IP na lista de bloqueio com validação de bloqueio temporário aplicado.
    blocklist.set('192.168.1.200', Date.now()); // Exemplo de IP Bloqueado Imediatamente
};

// Função para calcular o tempo para desbloqueio
const calculateUnblockTime = (blockTime) => {
    const unblockTime = new Date(blockTime + 12 * 60 * 60 * 1000).toISOString();
    return unblockTime;
};

// Função para checar se o tráfego deve ser bloqueado, permitido ou marcado
const checkTraffic = (traffic) => {
    const { ClientIP, ClientRequestPath, ClientSrcPort } = traffic;
    const timestamp = new Date().toISOString();

    // Atualização do access log por Endereço IP
    if (!accessLog.has(ClientIP)) {
        accessLog.set(ClientIP, []);
    }
    accessLog.get(ClientIP).push(Date.now());

    // Validar 3 tentativas em menos de 1 minuto
    const accessTimes = accessLog.get(ClientIP);
    if (accessTimes.length >= 3) {
        const firstAttemptTime = accessTimes[accessTimes.length - 3];
        if (Date.now() - firstAttemptTime < 60 * 1000) { // 1 minuto
            const unblockTime = calculateUnblockTime(Date.now());
            blockedIPs.push({ IP: ClientIP, Port: ClientSrcPort, Reason: 'Rapid Access Attempts', RequestPath: ClientRequestPath, TimeStamp: timestamp, UnblockTime: unblockTime });
            attackAttempts.push({ IP: ClientIP, Port: ClientSrcPort, Threat: 'Rapid Access Attempts', RequestPath: ClientRequestPath, TimeStamp: timestamp, UnblockTime: unblockTime });
            blocklist.set(ClientIP, Date.now());
            return 'Blocked';
        }
    }

    // Checar lista de bloqueios
    if (blocklist.has(ClientIP)) {
        const blockTime = blocklist.get(ClientIP);
        if (Date.now() - blockTime < 12 * 60 * 60 * 1000) { // 12 horas
            const unblockTime = calculateUnblockTime(blockTime);
            blockedIPs.push({ IP: ClientIP, Port: ClientSrcPort, Reason: 'Blocklist', RequestPath: ClientRequestPath, TimeStamp: timestamp, UnblockTime: unblockTime });
            flaggedIPs.push({ IP: ClientIP, Port: ClientSrcPort, Reason: 'Blocklist', RequestPath: ClientRequestPath, TimeStamp: timestamp, UnblockTime: unblockTime });
            return 'Blocked';
        } else {
            blocklist.delete(ClientIP); // Remover IPs bloqueados já expirados
        }
    }

    // Checando lista de permissão
    if (allowlist.has(ClientIP)) {
        allowedIPs.push({ IP: ClientIP, Port: ClientSrcPort, Reason: 'Allowlist', RequestPath: ClientRequestPath, TimeStamp: timestamp });
        return 'Allowed';
    }

    // Checagem de Ameaças
    for (const [key, { pattern, severity }] of Object.entries(patterns)) {
        if (pattern.test(ClientRequestPath)) {
            const unblockTime = severity === 'High' || severity === 'Medium'
                ? calculateUnblockTime(Date.now())
                : null;

            attackAttempts.push({ IP: ClientIP, Port: ClientSrcPort, Threat: key, RequestPath: ClientRequestPath, TimeStamp: timestamp, UnblockTime: unblockTime });

            if (severity === 'High') {
                blockedIPs.push({ IP: ClientIP, Port: ClientSrcPort, Reason: key, RequestPath: ClientRequestPath, TimeStamp: timestamp, UnblockTime: unblockTime });
                blocklist.set(ClientIP, Date.now());
                return 'Blocked';
            } else if (severity === 'Medium') {
                flaggedIPs.push({ IP: ClientIP, Port: ClientSrcPort, Reason: key, RequestPath: ClientRequestPath, TimeStamp: timestamp, UnblockTime: unblockTime });
                blockedIPs.push({ IP: ClientIP, Port: ClientSrcPort, Reason: key, RequestPath: ClientRequestPath, TimeStamp: timestamp, UnblockTime: unblockTime });
                blocklist.set(ClientIP, Date.now());
                return 'Flagged and Blocked';
            } else if (severity === 'Low') {
                flaggedIPs.push({ IP: ClientIP, Port: ClientSrcPort, Reason: key, RequestPath: ClientRequestPath, TimeStamp: timestamp });
                return 'Flagged';
            }
        }
    }

    // Ação Padrão
    allowedIPs.push({ IP: ClientIP, Port: ClientSrcPort, Reason: 'Default', RequestPath: ClientRequestPath, TimeStamp: timestamp });
    return 'Allowed';
};

// Função para escrever os dados em arquivos .csv
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

// Processando CSV usando PapaParse
const processCSV = (filePath) => {
    loadLists(); // Leitura de Lista de Permissão e blocklist

    const fileContent = fs.readFileSync(filePath, 'utf8');

    Papa.parse(fileContent, {
        header: true,
        step: (result) => {
            const row = result.data;
            checkTraffic(row); // Processamento de cada linha
        },
        complete: () => {
            console.log('CSV file successfully processed.');

            // Escrita dos relatórios em arquivos CSV distintos separados por Bloqueados, Marcados e Permitidos
            writeToCSV(blockedFilePath, blockedIPs, 'Blocked IPs report');
            writeToCSV(flaggedFilePath, flaggedIPs, 'Flagged IPs report');
            writeToCSV(allowedFilePath, allowedIPs, 'Allowed IPs report');
            writeToCSV(attackAttemptsFilePath, attackAttempts, 'Attack Attempts report');

            console.log('Reports generation completed.');
        },
        error: (err) => {
            console.error('Error processing CSV file:', err.message);
        }
    });
};

// Usabilidade - Executar o js na mesma pasta em que se contém a base de dados .csv
processCSV(inputFilePath);
