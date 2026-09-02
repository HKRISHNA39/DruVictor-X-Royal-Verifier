"use strict";

const express = require("express");
const path = require("path");
const dns = require("dns").promises;
const net = require("net");

const app = express();

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, "public");

app.disable("x-powered-by");

app.use(express.json({
    limit: "250kb"
}));

app.use(express.urlencoded({
    extended: false,
    limit: "250kb"
}));

app.use(express.static(PUBLIC_DIR));

/* =========================================================
   CONSTANTS
========================================================= */

const MAX_AD_LENGTH = 50000;
const MAX_WEBSITE_LENGTH = 2048;
const REQUEST_TIMEOUT = 10000;
const MAX_REDIRECTS = 3;


/* =========================================================
   HELPER FUNCTIONS
========================================================= */

function clampScore(score) {

    const number = Number(score);

    if (!Number.isFinite(number)) {
        return 0;
    }

    return Math.max(
        0,
        Math.min(100, Math.round(number))
    );
}


function verdictForScore(score) {

    if (score >= 70) {
        return "HIGH RISK";
    }

    if (score >= 35) {
        return "SUSPICIOUS";
    }

    return "LOW RISK";
}


function levelForPoints(points) {

    if (points >= 20) {
        return "high";
    }

    if (points >= 10) {
        return "medium";
    }

    return "low";
}


function normalizeText(text) {

    return String(text || "")
        .normalize("NFKC")
        .replace(/\s+/g, " ")
        .trim();
}


function containsAny(text, patterns) {

    return patterns.some(pattern => {

        if (pattern instanceof RegExp) {
            return pattern.test(text);
        }

        return text.includes(pattern);
    });
}


/* =========================================================
   LANGUAGE DETECTION
========================================================= */

function detectLanguage(text) {

    const value = String(text || "");

    const counts = {
        English: 0,
        Hindi: 0,
        Telugu: 0,
        Tamil: 0,
        Bengali: 0
    };

    for (const char of value) {

        const code = char.codePointAt(0);

        if (
            (code >= 0x0900 && code <= 0x097F)
        ) {
            counts.Hindi++;
        }

        else if (
            (code >= 0x0C00 && code <= 0x0C7F)
        ) {
            counts.Telugu++;
        }

        else if (
            (code >= 0x0B80 && code <= 0x0BFF)
        ) {
            counts.Tamil++;
        }

        else if (
            (code >= 0x0980 && code <= 0x09FF)
        ) {
            counts.Bengali++;
        }

        else if (
            (code >= 0x0041 && code <= 0x005A) ||
            (code >= 0x0061 && code <= 0x007A)
        ) {
            counts.English++;
        }
    }

    const winner =
        Object.entries(counts)
            .sort((a, b) => b[1] - a[1])[0];

    if (!winner || winner[1] === 0) {
        return "Unknown";
    }

    return winner[0];
}


/* =========================================================
   ADVERTISEMENT DETECTION RULES
========================================================= */

const AD_RULES = [

    {
        key: "payment",
        points: 30,
        icon: "💳",
        level: "high",

        patterns: [
            "pay registration fee",
            "registration fee",
            "processing fee",
            "security deposit",
            "refundable deposit",
            "visa fee",
            "pay before joining",
            "pay before interview",
            "advance payment",
            "send money",
            "transfer money",
            "pay us first",
            "deposit required",
            "joining fee",
            "placement fee",
            "consultancy fee",
            "money transfer",

            "पंजीकरण शुल्क",
            "रजिस्ट्रेशन फीस",
            "सिक्योरिटी डिपॉजिट",
            "पहले पैसे",
            "अग्रिम भुगतान",
            "जॉइनिंग फीस",

            "రిజిస్ట్రేషన్ ఫీజు",
            "సెక్యూరిటీ డిపాజిట్",
            "ముందుగా డబ్బు",
            "అడ్వాన్స్ పేమెంట్",

            "பதிவு கட்டணம்",
            "பாதுகாப்பு வைப்பு",
            "முன்பணம்",
            "முதலில் பணம்",

            "রেজিস্ট্রেশন ফি",
            "সিকিউরিটি ডিপোজিট",
            "আগে টাকা",
            "অগ্রিম পেমেন্ট"
        ]
    },

    {
        key: "noExperience",
        points: 15,
        icon: "🎓",
        level: "medium",

        patterns: [
            "no experience required",
            "no experience needed",
            "without experience",
            "experience not required",
            "freshers guaranteed",
            "anyone can apply",
            "10th pass",
            "12th pass",

            "बिना अनुभव",
            "अनुभव की आवश्यकता नहीं",
            "कोई अनुभव नहीं",

            "అనుభవం అవసరం లేదు",
            "అనుభవం లేకపోయినా",

            "அனுபவம் தேவையில்லை",

            "অভিজ্ঞতা প্রয়োজন নেই"
        ]
    },

    {
        key: "urgency",
        points: 20,
        icon: "⏰",
        level: "high",

        patterns: [
            "apply today",
            "apply now",
            "limited seats",
            "limited vacancies",
            "act immediately",
            "urgent hiring",
            "urgent vacancy",
            "last chance",
            "only today",
            "offer expires",
            "immediate joining",
            "immediate start",

            "आज ही आवेदन",
            "तुरंत आवेदन",
            "सीमित सीट",
            "तुरंत जॉइनिंग",

            "వెంటనే దరఖాస్తు",
            "పరిమిత ఖాళీలు",

            "உடனே விண்ணப்பிக்கவும்",
            "வரையறுக்கப்பட்ட பணியிடங்கள்",

            "আজই আবেদন",
            "সীমিত পদ"
        ]
    },

    {
        key: "messaging",
        points: 15,
        icon: "💬",
        level: "medium",

        patterns: [
            "contact on whatsapp",
            "message on whatsapp",
            "whatsapp only",
            "telegram only",
            "contact me on telegram",
            "dm to apply",
            "send cv on whatsapp",
            "send resume on whatsapp",
            "whatsapp number",

            "व्हाट्सऐप पर संपर्क",
            "व्हाट्सऐप पर भेजें",

            "వాట్సాప్‌లో సంప్రదించండి",
            "వాట్సాప్‌లో పంపండి",

            "வாட்ஸ்அப்பில் தொடர்பு",
            "வாட்ஸ்அப்பில் அனுப்பவும்",

            "হোয়াটসঅ্যাপে যোগাযোগ"
        ]
    },

    {
        key: "personalData",
        points: 20,
        icon: "🪪",
        level: "high",

        patterns: [
            "send aadhaar",
            "send aadhar",
            "aadhaar card",
            "aadhar card",
            "passport copy",
            "bank account",
            "bank details",
            "atm card",
            "debit card",
            "credit card",
            "otp",
            "upi pin",
            "password",
            "send your id",
            "identity proof",

            "आधार कार्ड",
            "बैंक विवरण",
            "ओटीपी",
            "पासवर्ड",

            "ఆధార్ కార్డు",
            "బ్యాంక్ వివరాలు",
            "ఓటీపీ",
            "పాస్వర్డ్",

            "ஆதார் அட்டை",
            "வங்கி விவரங்கள்",
            "ஓடிபி",
            "கடவுச்சொல்",

            "আধার কার্ড",
            "ব্যাংক বিবরণ",
            "ওটিপি",
            "পাসওয়ার্ড"
        ]
    },

    {
        key: "foreign",
        points: 15,
        icon: "🌍",
        level: "medium",

        patterns: [
            "work abroad",
            "foreign job",
            "overseas job",
            "international job",
            "work in europe",
            "work in canada",
            "work in dubai",
            "work in usa",
            "work in uk",
            "work visa guaranteed",
            "visa guaranteed",
            "100% visa",

            "विदेश में नौकरी",
            "विदेशी नौकरी",
            "वीजा गारंटी",

            "విదేశీ ఉద్యోగం",
            "వీసా గ్యారంటీ",

            "வெளிநாட்டு வேலை",
            "விசா உத்தரவாதம்",

            "বিদেশে চাকরি",
            "ভিসা গ্যারান্টি"
        ]
    },

    {
        key: "dangerous",
        points: 25,
        icon: "🚨",
        level: "high",

        patterns: [
            "illegal work",
            "fake documents",
            "fake passport",
            "guaranteed government job",
            "guaranteed job",
            "pay and get job",
            "job guaranteed after payment",
            "use someone else's documents",
            "no verification required",
            "bypass verification",

            "फर्जी दस्तावेज",
            "सरकारी नौकरी की गारंटी",
            "पैसे दो नौकरी लो",

            "నకిలీ పత్రాలు",
            "ప్రభుత్వ ఉద్యోగం గ్యారంటీ",

            "போலி ஆவணங்கள்",
            "அரசு வேலை உத்தரவாதம்",

            "জাল নথি",
            "সরকারি চাকরির গ্যারান্টি"
        ]
    },

    {
        key: "onlineOnly",
        points: 10,
        icon: "💻",
        level: "medium",

        patterns: [
            "online interview only",
            "online only",
            "work from home guaranteed",
            "easy online job",
            "earn from home",
            "easy money",
            "daily income guaranteed",
            "guaranteed income",
            "instant income",

            "घर बैठे कमाई",
            "गारंटीड कमाई",
            "ऑनलाइन नौकरी",

            "ఇంటి నుంచే పని",
            "గ్యారంటీ ఆదాయం",

            "வீட்டிலிருந்து வேலை",
            "உத்தரவாத வருமானம்",

            "বাড়িতে বসে কাজ",
            "গ্যারান্টিযুক্ত আয়"
        ]
    }
];


/* =========================================================
   JOB CONTEXT
========================================================= */

const JOB_WORDS = [
    "job",
    "jobs",
    "career",
    "vacancy",
    "vacancies",
    "recruitment",
    "recruiting",
    "hiring",
    "employment",
    "work",
    "position",
    "salary",
    "worker",
    "employee",
    "recruitment agent",
    "विदेशी नौकरी",
    "नौकरी",
    "भर्ती",
    "रोजगार",
    "ఉద్యోగం",
    "నియామకం",
    "வேலை",
    "ஆட்சேர்ப்பு",
    "চাকরি",
    "নিয়োগ"
];


/* =========================================================
   LICENCE DETECTION
========================================================= */

function extractMEALicence(text) {

    const patterns = [

        /\bRA\s*LICEN[CS]E\s*(?:NO\.?|NUMBER)?\s*[:#-]?\s*([A-Z0-9/-]{4,30})\b/i,

        /\bRECRUITING\s+AGENT\s*(?:LICEN[CS]E)?\s*(?:NO\.?|NUMBER)?\s*[:#-]?\s*([A-Z0-9/-]{4,30})\b/i,

        /\bRC\s*(?:NO\.?|NUMBER)\s*[:#-]?\s*([A-Z0-9/-]{4,30})\b/i,

        /\bLICEN[CS]E\s*(?:NO\.?|NUMBER)\s*[:#-]?\s*([A-Z0-9/-]{4,30})\b/i,

        /\bRA\s*[:#-]\s*([A-Z0-9/-]{4,30})\b/i
    ];

    for (const pattern of patterns) {

        const match = String(text).match(pattern);

        if (match && match[1]) {

            return {
                found: true,
                number: match[1].trim(),
                status: "NUMBER DETECTED — VERIFY OFFICIALLY"
            };
        }
    }

    return {
        found: false,
        number: "",
        status: "NOT FOUND"
    };
}


/* =========================================================
   ADVERTISEMENT ANALYSIS
========================================================= */

function analyzeAdvertisement(input) {

    const text = normalizeText(input);
    const lower = text.toLowerCase();

    let score = 0;
    const indicators = [];
    const matchedRules = new Set();

    for (const rule of AD_RULES) {

        const found = rule.patterns.some(pattern => {

            return lower.includes(
                String(pattern).toLowerCase()
            );
        });

        if (found) {

            score += rule.points;

            matchedRules.add(rule.key);

            indicators.push({
                icon: rule.icon,
                level: rule.level,
                text: getRuleMessage(rule.key)
            });
        }
    }


    const hasJobContext =
        containsAny(lower, JOB_WORDS.map(x => x.toLowerCase()));


    if (!hasJobContext) {

        indicators.push({
            icon: "ℹ️",
            level: "low",
            text: "The text does not clearly contain common recruitment/job terminology."
        });
    }


    /* Multiple warning signals increase concern. */

    if (matchedRules.size >= 3) {

        score += 10;

        indicators.push({
            icon: "⚠️",
            level: "medium",
            text: "Multiple recruitment warning signals were detected together."
        });
    }


    /* Excessive guarantee language. */

    const guaranteeMatches =
        lower.match(
            /\b(100%|guaranteed|guarantee|sure job|fixed job)\b/gi
        ) || [];

    if (guaranteeMatches.length >= 2) {

        score += 10;

        indicators.push({
            icon: "🎯",
            level: "medium",
            text: "Repeated guaranteed-job or guaranteed-income language was detected."
        });
    }


    /* Contact-number detection is informational only. */

    const phoneMatches =
        text.match(
            /(?:\+?\d[\d\s().-]{7,}\d)/g
        ) || [];

    if (phoneMatches.length > 0) {

        indicators.push({
            icon: "📞",
            level: "low",
            text: "A contact number appears in the advertisement. Verify who controls it before contacting."
        });
    }


    /* URL detection. */

    const urls =
        text.match(
            /https?:\/\/[^\s]+/gi
        ) || [];

    if (urls.length > 0) {

        indicators.push({
            icon: "🔗",
            level: "low",
            text: "One or more website links were detected. Check the destination independently."
        });
    }


    if (indicators.length === 0) {

        indicators.push({
            icon: "✅",
            level: "low",
            text: "No major predefined recruitment warning patterns were detected."
        });
    }


    score = clampScore(score);

    const licence =
        extractMEALicence(text);


    return {
        riskScore: score,
        verdict: verdictForScore(score),
        language: detectLanguage(text),
        meaLicence: licence,
        indicators
    };
}


function getRuleMessage(key) {

    const messages = {

        payment:
            "Payment, deposit, registration-fee or advance-money language was detected.",

        noExperience:
            "The advertisement emphasizes little or no experience requirements.",

        urgency:
            "Urgency or pressure-to-apply language was detected.",

        messaging:
            "The advertisement directs applicants toward messaging platforms for recruitment.",

        personalData:
            "Sensitive identity, banking, OTP or account information is requested or mentioned.",

        foreign:
            "Foreign/overseas employment or visa-related claims were detected.",

        dangerous:
            "Potentially unsafe, deceptive or illegal-job language was detected.",

        onlineOnly:
            "Easy online/work-from-home or guaranteed-income claims were detected."
    };

    return messages[key] ||
        "A recruitment warning signal was detected.";
}


/* =========================================================
   WEBSITE SECURITY HELPERS
========================================================= */

function isPrivateIPv4(ip) {

    const parts = ip.split(".").map(Number);

    if (
        parts.length !== 4 ||
        parts.some(
            n => !Number.isInteger(n) || n < 0 || n > 255
        )
    ) {
        return false;
    }

    const [a, b] = parts;

    if (a === 10) return true;

    if (a === 127) return true;

    if (a === 169 && b === 254) return true;

    if (a === 172 && b >= 16 && b <= 31) return true;

    if (a === 192 && b === 168) return true;

    if (a === 0) return true;

    return false;
}


function isPrivateIPv6(ip) {

    const value = ip.toLowerCase();

    return (
        value === "::1" ||
        value.startsWith("fc") ||
        value.startsWith("fd") ||
        value.startsWith("fe80:")
    );
}


function isBlockedIP(ip) {

    const version = net.isIP(ip);

    if (version === 4) {
        return isPrivateIPv4(ip);
    }

    if (version === 6) {
        return isPrivateIPv6(ip);
    }

    return true;
}


async function validateHostname(hostname) {

    const cleanHost =
        String(hostname || "")
            .toLowerCase()
            .replace(/\.$/, "");


    if (!cleanHost) {
        throw new Error("Website hostname is missing.");
    }


    if (
        cleanHost === "localhost" ||
        cleanHost.endsWith(".localhost") ||
        cleanHost.endsWith(".local")
    ) {
        throw new Error("Local addresses cannot be inspected.");
    }


    if (net.isIP(cleanHost)) {

        if (isBlockedIP(cleanHost)) {
            throw new Error("Private or local IP addresses are not allowed.");
        }

        return;
    }


    const addresses =
        await dns.lookup(
            cleanHost,
            {
                all: true,
                verbatim: true
            }
        );


    if (!addresses || addresses.length === 0) {
        throw new Error("Unable to resolve the website hostname.");
    }


    for (const address of addresses) {

        if (isBlockedIP(address.address)) {

            throw new Error(
                "The website resolves to a private/local network address and cannot be inspected."
            );
        }
    }
}


/* =========================================================
   WEBSITE URL VALIDATION
========================================================= */

function parseWebsiteURL(value) {

    let urlString =
        String(value || "").trim();


    if (!urlString) {
        throw new Error("Please enter a website URL.");
    }


    if (!/^https?:\/\//i.test(urlString)) {

        urlString =
            "https://" + urlString;
    }


    if (urlString.length > MAX_WEBSITE_LENGTH) {

        throw new Error(
            "The website URL is too long."
        );
    }


    let parsed;

    try {

        parsed =
            new URL(urlString);

    }

    catch {

        throw new Error(
            "Invalid website URL."
        );
    }


    if (
        parsed.protocol !== "http:" &&
        parsed.protocol !== "https:"
    ) {

        throw new Error(
            "Only HTTP and HTTPS websites are supported."
        );
    }


    if (parsed.username || parsed.password) {

        throw new Error(
            "Website URLs containing usernames or passwords are not allowed."
        );
    }


    parsed.hash = "";


    return parsed;
}


/* =========================================================
   GOVERNMENT DOMAIN DETECTION
========================================================= */

function isGovernmentDomain(hostname) {

    const host =
        String(hostname || "")
            .toLowerCase()
            .replace(/\.$/, "");


    /*
       India government domains commonly use .gov.in.
       This is a domain-pattern check only; it does NOT
       prove that the website itself is genuine.
    */

    return (
        host === "gov.in" ||
        host.endsWith(".gov.in")
    );
}


/* =========================================================
   WEBSITE FETCH
========================================================= */

async function fetchWebsiteSafely(startURL) {

    let currentURL =
        new URL(startURL.toString());


    let redirects = 0;


    while (true) {

        await validateHostname(
            currentURL.hostname
        );


        const controller =
            new AbortController();


        const timer =
            setTimeout(
                () => controller.abort(),
                REQUEST_TIMEOUT
            );


        let response;


        try {

            response =
                await fetch(
                    currentURL,
                    {
                        method: "GET",

                        redirect: "manual",

                        signal: controller.signal,

                        headers: {
                            "User-Agent":
                                "DruVictor-X-Royal-Verifier/2.0"
                        }
                    }
                );

        }

        catch (error) {

            if (error.name === "AbortError") {

                throw new Error(
                    "Website inspection timed out."
                );
            }

            throw new Error(
                "Unable to connect to the website."
            );
        }

        finally {

            clearTimeout(timer);
        }


        const location =
            response.headers.get("location");


        if (
            response.status >= 300 &&
            response.status < 400 &&
            location
        ) {

            redirects++;

            if (redirects > MAX_REDIRECTS) {

                throw new Error(
                    "Too many website redirects."
                );
            }


            let nextURL;

            try {

                nextURL =
                    new URL(
                        location,
                        currentURL
                    );

            }

            catch {

                throw new Error(
                    "The website returned an invalid redirect."
                );
            }


            if (
                nextURL.protocol !== "http:" &&
                nextURL.protocol !== "https:"
            ) {

                throw new Error(
                    "Unsafe redirect protocol detected."
                );
            }


            currentURL =
                nextURL;

            continue;
        }


        const contentType =
            response.headers.get("content-type") || "";


        let body = "";


        if (
            contentType.includes("text/") ||
            contentType.includes("json") ||
            contentType.includes("javascript") ||
            contentType === ""
        ) {

            try {

                body =
                    await response.text();

                body =
                    body.slice(0, 300000);

            }

            catch {

                body = "";
            }
        }


        return {
            response,
            finalURL: currentURL,
            body
        };
    }
}


/* =========================================================
   WEBSITE ANALYSIS
========================================================= */

async function analyzeWebsite(urlString) {

    const parsed =
        parseWebsiteURL(urlString);


    const originalHostname =
        parsed.hostname;


    const government =
        isGovernmentDomain(
            originalHostname
        );


    const inspection =
        await fetchWebsiteSafely(parsed);


    const finalURL =
        inspection.finalURL;


    const finalGovernment =
        isGovernmentDomain(
            finalURL.hostname
        );


    const combinedText =
        normalizeText(
            inspection.body
                .replace(/<script[\s\S]*?<\/script>/gi, " ")
                .replace(/<style[\s\S]*?<\/style>/gi, " ")
                .replace(/<[^>]*>/g, " ")
        );


    const lower =
        combinedText.toLowerCase();


    let score = 0;

    const indicators = [];


    if (
        !government &&
        !finalGovernment
    ) {

        indicators.push({
            icon: "🌐",
            level: "low",
            text: "The website does not use an Indian .gov.in government domain."
        });
    }

    else {

        indicators.push({
            icon: "🇮🇳",
            level: "low",
            text: "The website uses an Indian .gov.in government domain pattern."
        });
    }


    if (
        containsAny(
            lower,
            AD_RULES
                .flatMap(rule => rule.patterns)
                .map(x => String(x).toLowerCase())
        )
    ) {

        score += 20;

        indicators.push({
            icon: "⚠️",
            level: "medium",
            text: "Recruitment warning language was detected on the inspected page."
        });
    }


    if (
        containsAny(
            lower,
            [
                "registration fee",
                "processing fee",
                "security deposit",
                "pay now",
                "advance payment",
                "send money",
                "visa fee"
            ]
        )
    ) {

        score += 30;

        indicators.push({
            icon: "💳",
            level: "high",
            text: "Payment or deposit-related recruitment language was detected."
        });
    }


    if (
        containsAny(
            lower,
            [
                "whatsapp only",
                "telegram only",
                "send cv on whatsapp",
                "contact on whatsapp"
            ]
        )
    ) {

        score += 10;

        indicators.push({
            icon: "💬",
            level: "medium",
            text: "Messaging-platform-only recruitment language was detected."
        });
    }


    if (
        containsAny(
            lower,
            [
                "guaranteed job",
                "100% job",
                "guaranteed visa",
                "100% visa",
                "guaranteed income"
            ]
        )
    ) {

        score += 20;

        indicators.push({
            icon: "🎯",
            level: "high",
            text: "Guaranteed employment, visa or income claims were detected."
        });
    }


    if (inspection.response.status >= 400) {

        score += 10;

        indicators.push({
            icon: "🌐",
            level: "medium",
            text: "The website returned an HTTP error status."
        });
    }


    if (!combinedText) {

        indicators.push({
            icon: "ℹ️",
            level: "low",
            text: "The page did not provide readable text for deeper content analysis."
        });
    }


    if (indicators.length === 0) {

        indicators.push({
            icon: "✅",
            level: "low",
            text: "No major predefined website warning patterns were detected."
        });
    }


    score =
        clampScore(score);


    return {

        riskScore: score,

        verdict:
            verdictForScore(score),

        url:
            finalURL.toString(),

        governmentDomain:
            government || finalGovernment,

        inspection:
            inspection.response.ok
                ? "Website responded successfully."
                : "Website responded with an HTTP error.",

        responseStatus:
            String(
                inspection.response.status
            ),

        indicators
    };
}


/* =========================================================
   API: ADVERTISEMENT
========================================================= */

app.post(
    "/api/check-advertisement",
    (req, res) => {

        try {

            const text =
                typeof req.body?.text === "string"
                    ? req.body.text.trim()
                    : "";


            if (!text) {

                return res.status(400).json({
                    error:
                        "Please provide a job advertisement."
                });
            }


            if (text.length > MAX_AD_LENGTH) {

                return res.status(413).json({
                    error:
                        "The advertisement is too long."
                });
            }


            const result =
                analyzeAdvertisement(text);


            return res.json(result);

        }

        catch (error) {

            console.error(
                "Advertisement error:",
                error
            );

            return res.status(500).json({
                error:
                    "Advertisement analysis failed."
            });
        }
    }
);


/* =========================================================
   API: WEBSITE
========================================================= */

app.post(
    "/api/check-website",
    async (req, res) => {

        try {

            const url =
                typeof req.body?.url === "string"
                    ? req.body.url.trim()
                    : "";


            if (!url) {

                return res.status(400).json({
                    error:
                        "Please provide a website URL."
                });
            }


            const result =
                await analyzeWebsite(url);


            return res.json(result);

        }

        catch (error) {

            console.error(
                "Website error:",
                error.message
            );


            const clientError =
                error.message ||
                "Website inspection failed.";


            return res.status(400).json({
                error: clientError
            });
        }
    }
);


/* =========================================================
   FALLBACK
========================================================= */

app.get("*splat", (req, res) => {

    res.sendFile(
        path.join(
            PUBLIC_DIR,
            "index.html"
        )
    );
});


/* =========================================================
   START SERVER
========================================================= */

app.listen(
    PORT,
    () => {

        console.log("");
        console.log(
            "=========================================="
        );

        console.log(
            "       DruVictor-X Royal Verifier"
        );

        console.log(
            "=========================================="
        );

        console.log(
            `Server running at http://localhost:${PORT}`
        );

        console.log(
            "Advertisement API:"
        );

        console.log(
            `POST http://localhost:${PORT}/api/check-advertisement`
        );

        console.log(
            "Website API:"
        );

        console.log(
            `POST http://localhost:${PORT}/api/check-website`
        );

        console.log(
            "=========================================="
        );

        console.log("");
    }
);
