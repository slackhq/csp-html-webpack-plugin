const cheerio = require('cheerio');
const crypto = require('crypto');
const uniq = require('lodash/uniq');
const compact = require('lodash/compact');
const flatten = require('lodash/flatten');
const isFunction = require('lodash/isFunction');
const get = require('lodash/get');

// Attempt to load HtmlWebpackPlugin@4
// Borrowed from https://github.com/waysact/webpack-subresource-integrity/blob/master/index.js
let HtmlWebpackPlugin;
try {
  // eslint-disable-next-line global-require
  HtmlWebpackPlugin = require('html-webpack-plugin');
} catch (e) {
  /* istanbul ignore next */
  if (!(e instanceof Error) || e.code !== 'MODULE_NOT_FOUND') {
    throw e;
  }
}

/**
 * The default function for adding the CSP to the head of a document
 * Can be overwritten to allow the developer to process the CSP in their own way
 * @param {string} builtPolicy
 * @param {object} htmlPluginData
 * @param {object} $
 */
const defaultProcessFn = (builtPolicy, htmlPluginData, $) => {
  let metaTag = $('meta[http-equiv="Content-Security-Policy"]');

  // Add element if it doesn't exist.
  if (!metaTag.length) {
    metaTag = cheerio.load('<meta http-equiv="Content-Security-Policy">')(
      'meta'
    );
    metaTag.prependTo($('head'));
  }

  // build the policy into the context attr of the csp meta tag
  metaTag.attr('content', builtPolicy);

  // eslint-disable-next-line no-param-reassign
  htmlPluginData.html = get(htmlPluginData, 'plugin.options.xhtml', false)
    ? $.xml()
    : $.html();
};

const defaultPolicy = {
  'base-uri': "'self'",
  'object-src': "'none'",
  'script-src': ["'unsafe-inline'", "'self'", "'unsafe-eval'"],
  'style-src': ["'unsafe-inline'", "'self'", "'unsafe-eval'"],
};

const defaultAdditionalOpts = {
  enabled: true,
  hashingMethod: 'sha256',
  hashEnabled: {
    'script-src': true,
    'style-src': true,
  },
  nonceEnabled: {
    'script-src': true,
    'style-src': true,
  },
  processFn: defaultProcessFn,
};

class CspHtmlWebpackPlugin {
  /**
   * Setup for our plugin
   * @param {object} policy - the policy object - see defaultPolicy above for the structure
   * @param {object} additionalOpts - additional config options - see defaultAdditionalOpts above for options available
   */
  constructor(policy = {}, additionalOpts = {}) {
    // the policy passed in from the CspHtmlWebpackPlugin instance
    this.cspPluginPolicy = Object.freeze(policy);

    // the additional options that this plugin allows
    this.opts = Object.freeze({ ...defaultAdditionalOpts, ...additionalOpts });

    // valid hashes from https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src#Sources
    if (!['sha256', 'sha384', 'sha512'].includes(this.opts.hashingMethod)) {
      throw new Error(
        `'${this.opts.hashingMethod}' is not a valid hashing method`
      );
    }
  }

  /**
   * Builds options based on settings passed into the CspHtmlWebpackPlugin instance, and the HtmlWebpackPlugin instance
   * Policy: combines default, csp instance and html webpack instance policies defined. Latter policy rules always override former
   * HashEnabled: sets whether we should add hashes for inline scripts/styles
   * NonceEnabled: sets whether we should add nonce attrs for external scripts/styles
   * @param {object} compilation - the webpack compilation object
   * @param {object} htmlPluginData - the HtmlWebpackPlugin data object
   * @param {function} compileCb - the callback function to continue webpack compilation
   */
  mergeOptions(compilation, htmlPluginData, compileCb) {
    // 1. Let's create the policy we want to use for this HtmlWebpackPlugin instance
    // CspHtmlWebpackPlugin and HtmlWebpackPlugin policies merged
    const userPolicy = Object.freeze({
      ...this.cspPluginPolicy,
      ...get(htmlPluginData, 'plugin.options.cspPlugin.policy', {}),
    });

    // defaultPolicy and userPolicy merged
    this.policy = Object.freeze({ ...defaultPolicy, ...userPolicy });

    // and now validate it
    this.validatePolicy(compilation);

    // 2. Lets set which hashes and nonces are enabled for this HtmlWebpackPlugin instance
    this.hashEnabled = Object.freeze({
      ...this.opts.hashEnabled,
      ...get(htmlPluginData, 'plugin.options.cspPlugin.hashEnabled', {}),
    });

    this.nonceEnabled = Object.freeze({
      ...this.opts.nonceEnabled,
      ...get(htmlPluginData, 'plugin.options.cspPlugin.nonceEnabled', {}),
    });

    // 3. Get the processFn for this HtmlWebpackPlugin instance.
    this.processFn = get(
      htmlPluginData,
      'plugin.options.cspPlugin.processFn',
      this.opts.processFn
    );

    return compileCb(null, htmlPluginData);
  }

  /**
   * Validate the policy by making sure that all static sources have been wrapped in apostrophes
   * i.e. policy should contain 'self' instead of self
   * @param {object} compilation - the webpack compilation object
   */
  validatePolicy(compilation) {
    const staticSources = [
      'self',
      'unsafe-inline',
      'unsafe-eval',
      'none',
      'strict-dynamic',
      'report-sample',
    ];
    const sourcesRegexes = staticSources.map(
      (source) => new RegExp(`\\s${source}\\s`)
    );

    Object.keys(this.policy).forEach((key) => {
      const val = Array.isArray(this.policy[key])
        ? compact(uniq(this.policy[key])).join(' ')
        : this.policy[key];

      for (let i = 0, len = sourcesRegexes.length; i < len; i += 1) {
        if (` ${val} `.match(sourcesRegexes[i])) {
          compilation.errors.push(
            new Error(
              `CSP: policy for ${key} contains ${staticSources[i]} which should be wrapped in apostrophes`
            )
          );
        }
      }
    });
  }

  /**
   * Checks to see whether the plugin is enabled. this.opts.enabled can be a function or bool here
   * @param htmlPluginData - the htmlPluginData from compilation
   * @return {boolean} - whether the plugin is enabled or not
   */
  isEnabled(htmlPluginData) {
    const cspPluginEnabled = get(
      htmlPluginData,
      'plugin.options.cspPlugin.enabled'
    );
    if (cspPluginEnabled === false) {
      // the HtmlWebpackPlugin instance has disabled the plugin
      return false;
    }

    if (isFunction(this.opts.enabled)) {
      // run the function to check if the plugin has been disabled
      return this.opts.enabled(htmlPluginData);
    }

    // otherwise assume it's a boolean
    return this.opts.enabled;
  }

  /**
   * Create a random nonce which we will set onto our assets
   * @return {string}
   */
  // eslint-disable-next-line class-methods-use-this
  createNonce() {
    return crypto.randomBytes(16).toString('base64');
  }

  /**
   * Generates nonces for the policy / selector we define
   * @param {object} $ - the Cheerio instance
   * @param {string} policyName - one of 'script-src' and 'style-src'
   * @param {string} selector - a Cheerio selector string for getting the hashable elements for this policy
   * @return {string[]}
   */
  setNonce($, policyName, selector) {
    if (this.nonceEnabled[policyName] === false) {
      // we don't want to add any nonce for this specific policy
      return [];
    }

    const policy = this.policy[policyName];
    const policyStr = Array.isArray(policy) ? policy.join(' ') : policy;

    // get a list of already defined urls for this policy type
    const urls = policyStr.match(/https?:\/\/[^'"]+/g) || [];

    // check if the user has defined 'strict-dynamic' in their policy
    // if so, we will need to include the nonce even if the domain has been whitelisted for it
    const hasStrictDynamic = policyStr.includes("'strict-dynamic'");

    return $(selector)
      .map((i, element) => {
        // get the src/href and check if it's already been whitelisted by the user.
        // if it has, and the dev hasn't defined strict-dynamic, there's no reason to add a nonce for it
        if (!hasStrictDynamic) {
          const srcOrHref = $(element).attr('src') || $(element).attr('href');
          for (let j = 0, len = urls.length; j < len; j += 1) {
            if (srcOrHref.startsWith(urls[j])) {
              return null;
            }
          }
        }

        // create a nonce, and attach to the script tag
        const nonce = this.createNonce();
        $(element).attr('nonce', nonce);

        // return in the format csp needs
        return `'nonce-${nonce}'`;
      })
      .filter((entry) => entry !== null)
      .get();
  }

  /**
   * Hashes a string using the hashing method we have opted for and then base64 encodes the result
   * @param {string} str - the string to hash
   * @returns {string} - the returned hash with the hashing method prepended e.g. sha256-123456abcdef
   */
  hash(str) {
    const hashed = crypto
      .createHash(this.opts.hashingMethod)
      .update(str, 'utf8')
      .digest('base64');

    return `'${this.opts.hashingMethod}-${hashed}'`;
  }

  /**
   * Calculates shas of the policy / selector we define
   * @param {object} $ - the Cheerio instance
   * @param {string} policyName - one of 'script-src' and 'style-src'
   * @param {string} selector - a Cheerio selector string for getting the hashable elements for this policy
   * @return {string[]}
   */
  getShas($, policyName, selector) {
    if (this.hashEnabled[policyName] === false) {
      // we don't want to add any nonce for this specific policy
      return [];
    }

    return $(selector)
      .map((i, element) => this.hash($(element).html()))
      .get();
  }

  /**
   * Builds the CSP policy by flattening arrays into strings and appending all policies into a single string
   * @param policyObj
   * @returns {string}
   */
  // eslint-disable-next-line class-methods-use-this
  buildPolicy(policyObj) {
    return Object.keys(policyObj)
      .map((key) => {
        const val = Array.isArray(policyObj[key])
          ? compact(uniq(policyObj[key])).join(' ')
          : policyObj[key];

        // move strict dynamic to the end of the policy if it exists to be backwards compatible with csp2
        // https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src#strict-dynamic
        if (val.includes("'strict-dynamic'")) {
          const newVal = `${val
            .replace(/\s?'strict-dynamic'\s?/gi, ' ')
            .trim()} 'strict-dynamic'`;
          return `${key} ${newVal}`;
        }

        return `${key} ${val}`;
      })
      .join('; ');
  }

  /**
   * Processes HtmlWebpackPlugin's html data adding the CSP defined
   * @param htmlPluginData
   * @param compileCb
   */
  processCsp(compilation, htmlPluginData, compileCb) {
    const $ = cheerio.load(htmlPluginData.html, {
      decodeEntities: false,
      _useHtmlParser2: true,
      xmlMode: get(htmlPluginData, 'plugin.options.xhtml', false),
    });

    // if not enabled, remove the empty tag
    if (!this.isEnabled(htmlPluginData)) {
      return compileCb(null, htmlPluginData);
    }

    // get all nonces for script and style tags
    const scriptNonce = this.setNonce($, 'script-src', 'script[src]');
    const styleNonce = this.setNonce($, 'style-src', 'link[rel="stylesheet"]');

    // get all shas for script and style tags
    const scriptShas = this.getShas($, 'script-src', 'script:not([src])');
    const styleShas = this.getShas($, 'style-src', 'style:not([href])');

    const builtPolicy = this.buildPolicy({
      ...this.policy,
      'script-src': flatten([this.policy['script-src']]).concat(
        scriptShas,
        scriptNonce
      ),
      'style-src': flatten([this.policy['style-src']]).concat(
        styleShas,
        styleNonce
      ),
    });

    this.processFn(builtPolicy, htmlPluginData, $, compilation);

    return compileCb(null, htmlPluginData);
  }

  /**
   * Hooks into webpack to collect assets and hash them, build the policy, and add it into our HTML template
   * @param compiler
   */
  apply(compiler) {
    compiler.hooks.compilation.tap('CspHtmlWebpackPlugin', (compilation) => {
      HtmlWebpackPlugin.getHooks(compilation).beforeAssetTagGeneration.tapAsync(
        'CspHtmlWebpackPlugin',
        this.mergeOptions.bind(this, compilation)
      );
      HtmlWebpackPlugin.getHooks(compilation).beforeEmit.tapAsync(
        'CspHtmlWebpackPlugin',
        this.processCsp.bind(this, compilation)
      );
    });
  }
}

module.exports = CspHtmlWebpackPlugin;
