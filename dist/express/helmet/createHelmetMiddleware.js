"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createHelmetMiddleware = createHelmetMiddleware;
const helmet_1 = __importDefault(require("helmet"));
const ONE_YEAR_SECONDS = 31536000;
/** Append extras to a base directive, de-duplicating while preserving order. */
function extend(base, extra) {
    if (!extra || extra.length === 0)
        return base;
    const seen = new Set(base);
    const merged = [...base];
    for (const value of extra) {
        if (!seen.has(value)) {
            seen.add(value);
            merged.push(value);
        }
    }
    return merged;
}
/**
 * Deep-merge helmet overrides onto the preset-built options. Plain objects are
 * merged recursively; arrays and primitives from `override` replace the base.
 * This lets `overrides.contentSecurityPolicy.directives.scriptSrc` fully
 * replace a directive while leaving untouched directives intact.
 */
function isPlainObject(value) {
    return (typeof value === 'object' &&
        value !== null &&
        !Array.isArray(value) &&
        (Object.getPrototypeOf(value) === Object.prototype ||
            Object.getPrototypeOf(value) === null));
}
function deepMerge(base, override) {
    if (override === undefined)
        return base;
    if (!isPlainObject(base) || !isPlainObject(override)) {
        return override;
    }
    const result = { ...base };
    for (const key of Object.keys(override)) {
        result[key] = deepMerge(base[key], override[key]);
    }
    return result;
}
/**
 * Build a hardened helmet middleware. The CSP starts from a strict base
 * (default-src 'self'; object/frame 'none'; base-uri/form-action 'self') and
 * only widens where the caller supplies extra sources. `overrides` are applied
 * last and win over everything.
 */
function createHelmetMiddleware(config = {}) {
    const { csp = {}, allowUnsafeInlineStyles = false } = config;
    const hstsMaxAge = config.hstsMaxAge ?? ONE_YEAR_SECONDS;
    const styleBase = allowUnsafeInlineStyles
        ? ["'self'", "'unsafe-inline'"]
        : ["'self'"];
    const directives = {
        defaultSrc: ["'self'"],
        scriptSrc: extend(["'self'"], csp.scriptSrc),
        styleSrc: extend(styleBase, csp.styleSrc),
        connectSrc: extend(["'self'"], csp.connectSrc),
        fontSrc: extend(["'self'"], csp.fontSrc),
        imgSrc: extend(["'self'", 'data:', 'https:'], csp.imgSrc),
        // object/frame stay locked to 'none' UNLESS the caller extends them.
        objectSrc: ["'none'"],
        frameSrc: csp.frameSrc && csp.frameSrc.length > 0 ? csp.frameSrc : ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
    };
    if (csp.workerSrc && csp.workerSrc.length > 0) {
        directives.workerSrc = extend(["'self'"], csp.workerSrc);
    }
    const presetOptions = {
        contentSecurityPolicy: {
            useDefaults: false,
            directives,
        },
        hsts: {
            maxAge: hstsMaxAge,
            includeSubDomains: true,
            preload: true,
        },
    };
    const merged = deepMerge(presetOptions, config.overrides);
    return (0, helmet_1.default)(merged);
}
