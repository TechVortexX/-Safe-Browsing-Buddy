const loadingState = document.getElementById('loadingState');
const errorState = document.getElementById('errorState');
const resultsState = document.getElementById('resultsState');
const errorMessage = document.getElementById('errorMessage');
const currentUrlDisplay = document.getElementById('currentUrl');
const riskScoreDisplay = document.getElementById('riskScore');
const riskStatusDisplay = document.getElementById('riskStatus');
const issuesListDisplay = document.getElementById('issuesList');
const analyzeAgainBtn = document.getElementById('analyzeAgainBtn');
const retryButton = document.getElementById('retryButton');
const progressCircle = document.getElementById('progressCircle');

function analyzeURL(urlString) {
    const analysis = {
        score: 0,
        reasons: []
    };

    try {
        const url = new URL(urlString);
        const hostname = url.hostname;
        const fullUrl = url.toString();

        // 1. IP Address Detection
        const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;

        if (ipPattern.test(hostname)) {
            const parts = hostname.split('.');

            const isValidIP = parts.every(part => {
                const num = parseInt(part);
                return num >= 0 && num <= 255;
            });

            if (isValidIP) {
                analysis.score += 25;

                analysis.reasons.push({
                    title: 'IP Address Used',
                    description:
                        'Website uses an IP address instead of a domain name.',
                    severity: 'high'
                });
            }
        }

        // 2. Long URL Detection
        if (fullUrl.length > 100) {
            analysis.score += 5;

            analysis.reasons.push({
                title: 'Unusually Long URL',
                description:
                    `URL is exceptionally long (${fullUrl.length} characters).`,
                severity: 'medium'
            });
        }

        // 3. Excessive Subdomains
        const subdomainCount =
            (hostname.match(/\./g) || []).length;

        if (subdomainCount > 3) {
            analysis.score += 12;

            analysis.reasons.push({
                title: 'Excessive Subdomains',
                description:
                    `URL has ${subdomainCount} levels.`,
                severity: 'medium'
            });
        }

        // 4. Suspicious Keywords
        const suspiciousKeywords = [
            'verify',
            'confirm',
            'urgent',
            'account',
            'login',
            'signin',
            'update',
            'validate',
            'authenticate',
            'security'
        ];

        const lowerUrl = fullUrl.toLowerCase();

        let keywordMatches = 0;

        suspiciousKeywords.forEach(keyword => {
            if (lowerUrl.includes(keyword)) {
                keywordMatches++;
            }
        });

        if (keywordMatches > 0) {
            analysis.score += Math.min(
                15,
                keywordMatches * 5
            );

            analysis.reasons.push({
                title: 'Suspicious Keywords Detected',
                description:
                    `Found ${keywordMatches} suspicious keyword(s).`,
                severity: 'medium'
            });
        }

        // 5. Impersonation Detection
        const impersonationPattern =
            /paypal|amazon|apple|google|microsoft|bank|security/i;

        if (
            impersonationPattern.test(hostname) &&
            !isKnownDomain(hostname)
        ) {
            analysis.score += 18;

            analysis.reasons.push({
                title: 'Potential Impersonation',
                description:
                    'Domain resembles a popular service.',
                severity: 'high'
            });
        }

        // 6. Multiple Hyphens
        const domainPart = hostname.split('.')[0];

        const hyphenCount =
            (domainPart.match(/-/g) || []).length;

        if (hyphenCount >= 2) {
            analysis.score += 8;

            analysis.reasons.push({
                title: 'Multiple Hyphens in Domain',
                description:
                    `Domain contains ${hyphenCount} hyphens.`,
                severity: 'low'
            });
        }

        // 7. URL Shortener Detection
        const shortenerDomains = [
            'bit.ly',
            'tinyurl.com',
            'ow.ly',
            'short.link'
        ];

        if (shortenerDomains.includes(hostname)) {
            analysis.score += 20;

            analysis.reasons.push({
                title: 'URL Shortener Detected',
                description:
                    'This is a shortened URL.',
                severity: 'high'
            });
        }

        // 8. HTTP Detection
        if (url.protocol === 'http:') {
            analysis.score += 15;

            analysis.reasons.push({
                title: 'No HTTPS Encryption',
                description:
                    'Website uses HTTP instead of HTTPS.',
                severity: 'high'
            });
        }

        // 9. Excessive Numbers
        const numberRatio =
            (hostname.match(/\d/g) || []).length /
            hostname.length;

        if (numberRatio > 0.3) {
            analysis.score += 6;

            analysis.reasons.push({
                title: 'Excessive Numbers in Domain',
                description:
                    'Domain has an unusual number ratio.',
                severity: 'low'
            });
        }

        // 10. Non-Standard Port
        if (
            url.port &&
            !['80', '443'].includes(url.port)
        ) {
            analysis.score += 12;

            analysis.reasons.push({
                title: 'Non-Standard Port',
                description:
                    `Uses non-standard port ${url.port}.`,
                severity: 'medium'
            });
        }

        // Maximum score = 100
        analysis.score = Math.min(
            100,
            analysis.score
        );

    } catch (error) {
        console.error(
            'URL Analysis Error:',
            error
        );
    }

    return analysis;
}


// Check Trusted Domains
function isKnownDomain(hostname) {

    const knownDomains = [
        'paypal.com',
        'amazon.com',
        'apple.com',
        'google.com',
        'microsoft.com',
        'facebook.com',
        'youtube.com',
        'github.com',
        'wikipedia.org',
        'reddit.com'
    ];

    return knownDomains.some(domain =>
        hostname === domain ||
        hostname.endsWith('.' + domain)
    );
}


// Get Risk Level
function getRiskLevel(score) {

    if (score < 30) {
        return {
            level: 'Low Risk',
            class: 'low-risk',
            emoji: '✅'
        };
    }

    if (score < 60) {
        return {
            level: 'Suspicious',
            class: 'medium-risk',
            emoji: '⚠️'
        };
    }

    return {
        level: 'High Risk',
        class: 'high-risk',
        emoji: '🚨'
    };
}


// Update Progress Circle
function updateProgressCircle(score) {

    const radius = 45;

    const circumference =
        2 * Math.PI * radius;

    const offset =
        circumference -
        (score / 100) * circumference;

    progressCircle.style.strokeDashoffset =
        offset;

    progressCircle.classList.remove(
        'risk-low',
        'risk-medium',
        'risk-high'
    );

    if (score < 30) {
        progressCircle.classList.add(
            'risk-low'
        );
    }

    else if (score < 60) {
        progressCircle.classList.add(
            'risk-medium'
        );
    }

    else {
        progressCircle.classList.add(
            'risk-high'
        );
    }
}


// Display Results
function displayResults(url, analysis) {

    hideAllStates();

    resultsState.classList.remove(
        'hidden'
    );

    const displayUrl =
        url.length > 60
            ? url.substring(0, 57) + '...'
            : url;

    currentUrlDisplay.textContent =
        displayUrl;

    currentUrlDisplay.title =
        url;

    riskScoreDisplay.textContent =
        analysis.score;

    updateProgressCircle(
        analysis.score
    );

    const riskLevel =
        getRiskLevel(
            analysis.score
        );

    riskStatusDisplay.textContent =
        riskLevel.emoji +
        ' ' +
        riskLevel.level;

    riskStatusDisplay.className =
        'risk-status ' +
        riskLevel.class;


    // Display Issues
    if (analysis.reasons.length === 0) {

        issuesListDisplay.innerHTML =
            '<p class="no-issues">✅ No suspicious patterns detected.</p>';

    }

    else {

        issuesListDisplay.innerHTML =
            analysis.reasons
                .map(reason => `
                    <div class="issue-item">

                        <strong>
                            ⚠️ ${reason.title}
                        </strong>

                        ${reason.description}

                    </div>
                `)
                .join('');
    }
}


// Show Error
function showError(message) {

    hideAllStates();

    errorState.classList.remove(
        'hidden'
    );

    errorMessage.textContent =
        message;
}


// Hide All States
function hideAllStates() {

    loadingState.classList.add(
        'hidden'
    );

    errorState.classList.add(
        'hidden'
    );

    resultsState.classList.add(
        'hidden'
    );
}


// Get Current Tab URL
async function getCurrentTabUrl() {

    try {

        const [tab] =
            await chrome.tabs.query({
                active: true,
                currentWindow: true
            });

        if (!tab || !tab.url) {

            showError(
                'Unable to access current tab URL.'
            );

            return null;
        }

        try {

            new URL(tab.url);

            return tab.url;

        }

        catch {

            showError(
                'Current page URL cannot be analyzed.'
            );

            return null;
        }

    }

    catch (error) {

        console.error(
            'Error:',
            error
        );

        showError(
            'Error accessing tab information.'
        );

        return null;
    }
}


// Perform Analysis
async function performAnalysis() {

    hideAllStates();

    loadingState.classList.remove(
        'hidden'
    );

    const url =
        await getCurrentTabUrl();

    if (!url) {
        return;
    }

    await new Promise(
        resolve =>
            setTimeout(resolve, 500)
    );

    const analysis =
        analyzeURL(url);

    displayResults(
        url,
        analysis
    );
}


// Initialize Buttons
function initializeEventListeners() {

    analyzeAgainBtn.addEventListener(
        'click',
        performAnalysis
    );

    retryButton.addEventListener(
        'click',
        performAnalysis
    );
}


// Start Extension
document.addEventListener(
    'DOMContentLoaded',
    async () => {

        initializeEventListeners();

        await performAnalysis();
    }
);
