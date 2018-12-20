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
  if (!(e instanceof Error) || e.code !== 'MODULE_NOT_FOUND') {
    throw e;
  }
}

const defaultPolicy = {
  'base-uri': "'self'",
  'object-src': "'none'",
  'script-src': ["'unsafe-inline'", "'self'", "'unsafe-eval'"],
  'style-src': ["'unsafe-inline'", "'self'", "'unsafe-eval'"]
};

const defaultAdditionalOpts = {
  devAllowUnsafe: false,
  enabled: true,
  hashingMethod: 'sha256'
};

class CspHtmlWebpackPlugin {
  /**
   * Setup for our plugin
   * @param {object} policy - the policy object - see defaultPolicy above for the structure
   * @param {object} additionalOpts - additional config options - see defaultAdditionalOpts above for options available
   */
  constructor(policy = {}, additionalOpts = {}) {
    // the policy we want to use
    this.policy = Object.freeze(Object.assign({}, defaultPolicy, policy));
    this.userPolicy = Object.freeze(policy);

    // the additional options that this plugin allows
    this.opts = Object.assign({}, defaultAdditionalOpts, additionalOpts);

    // valid hashes from https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src#Sources
    if (!['sha256', 'sha384', 'sha512'].includes(this.opts.hashingMethod)) {
      throw new Error(
        `'${this.opts.hashingMethod}' is not a valid hashing method`
      );
    }
  }

  /**
   * Checks to see whether the plugin is enabled. this.opts.enabled can be a function or bool here
   * @param htmlPluginData - the htmlPluginData from compilation
   * @return {boolean} - whether the plugin is enabled or not
   */
  isEnabled(htmlPluginData) {
    const disableCspPlugin = get(
      htmlPluginData,
      'plugin.options.disableCspPlugin'
    );
    if (disableCspPlugin && disableCspPlugin === true) {
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
   * Helper function to return the correct policy depending on whether the dev has allowed unsafe eval/inline or not
   * @param {object} $ - the Cheerio instance
   * @param {string} policyName - one of 'script-src' and 'style-src'
   * @param {string} selector - a Cheerio selector string for getting the hashable elements for this policy
   * @return {object} the new policy for `policyName`
   */
  createPolicyObj($, policyName, selector) {
    if (
      this.opts.devAllowUnsafe === true &&
      this.userPolicy[policyName] &&
      (this.userPolicy[policyName].includes("'unsafe-inline'") ||
        this.userPolicy[policyName].includes("'unsafe-eval'"))
    ) {
      // the user has allowed us to override unsafe-*, and we found unsafe-* in their defined policy. Let's use it
      return this.userPolicy[policyName];
    }

    // otherwise hash all of the elements passed in
    const hashes = $(selector)
      .map((i, element) => this.hash($(element).html()))
      .get();

    return flatten([this.policy[policyName]]).concat(hashes);
  }

  /**
   * Builds the CSP policy by flattening arrays into strings and appending all policies into a single string
   * @param policyObj
   * @returns {string}
   */
  // eslint-disable-next-line class-methods-use-this
  buildPolicy(policyObj) {
    return Object.keys(policyObj)
      .map(key => {
        const val = Array.isArray(policyObj[key])
          ? compact(uniq(policyObj[key])).join(' ')
          : policyObj[key];

        return `${key} ${val}`;
      })
      .join('; ');
  }

  /**
   * Processes HtmlWebpackPlugin's html data adding the CSP defined
   * @param htmlPluginData
   * @param compileCb
   */
  processCsp(htmlPluginData, compileCb) {
    const $ = cheerio.load(htmlPluginData.html, {
      decodeEntities: false
    });

    let metaTag = $('meta[http-equiv="Content-Security-Policy"]');

    // if not enabled, remove the empty tag
    if (!this.isEnabled(htmlPluginData)) {
      metaTag.remove();

      // eslint-disable-next-line no-param-reassign
      htmlPluginData.html = $.html();

      return compileCb(null, htmlPluginData);
    }

    // Add element if it doesn't exist.
    if (!metaTag.length) {
      metaTag = cheerio.load('<meta http-equiv="Content-Security-Policy">')(
        'meta'
      );
      metaTag.prependTo($('head'));
    }

    // looks for script and style rules to hash
    const scriptRule = this.createPolicyObj(
      $,
      'script-src',
      'script:not([src])'
    );
    const styleRule = this.createPolicyObj($, 'style-src', 'style:not([href])');

    // build the policy into the context attr of the csp meta tag
    metaTag.attr(
      'content',
      this.buildPolicy({
        ...this.policy,
        'script-src': scriptRule,
        'style-src': styleRule
      })
    );

    // eslint-disable-next-line no-param-reassign
    htmlPluginData.html = $.html();

    return compileCb(null, htmlPluginData);
  }

  /**
   * Hooks into webpack to collect assets and hash them, build the policy, and add it into our HTML template
   * @param compiler
   */
  apply(compiler) {
    if (compiler.hooks) {
      compiler.hooks.compilation.tap('CspHtmlWebpackPlugin', compilation => {
        if (HtmlWebpackPlugin && HtmlWebpackPlugin.getHooks) {
          // HTMLWebpackPlugin@4
          HtmlWebpackPlugin.getHooks(compilation).beforeEmit.tapAsync(
            'CspHtmlWebpackPlugin',
            this.processCsp.bind(this)
          );
        } else {
          // HTMLWebpackPlugin@3
          compilation.hooks.htmlWebpackPluginAfterHtmlProcessing.tapAsync(
            'CspHtmlWebpackPlugin',
            this.processCsp.bind(this)
          );
        }
      });
    } else {
      compiler.plugin('compilation', compilation => {
        compilation.plugin(
          'html-webpack-plugin-after-html-processing',
          this.processCsp.bind(this)
        );
      });
    }
  }
}

module.exports = CspHtmlWebpackPlugin;
