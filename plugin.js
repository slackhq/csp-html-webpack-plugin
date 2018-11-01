const cheerio = require('cheerio');
const crypto = require('crypto');
const uniq = require('lodash/uniq');
const compact = require('lodash/compact');
const flatten = require('lodash/flatten');
const isFunction = require('lodash/isFunction');

const defaultPolicy = {
  'base-uri': "'self'",
  'object-src': "'none'",
  'script-src': ["'unsafe-inline'", "'self'", "'unsafe-eval'"],
  'style-src': ["'unsafe-inline'", "'self'", "'unsafe-eval'"]
};

const defaultAdditionalOpts = {
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
    this.policy = Object.assign({}, defaultPolicy, policy);
    this.userPolicy = policy;

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
    if (isFunction(this.opts.enabled)) {
      return this.opts.enabled(htmlPluginData);
    }

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
      metaTag.appendTo($('head'));
    }

    const policyObj = JSON.parse(JSON.stringify(this.policy));
    const parsedUserPolicy = JSON.parse(JSON.stringify(this.userPolicy));

    // If the user policy contains 'unsafe-inline' for either script-src or style-src, we need to
    // avoid hashing the existing script tags, so as to avoid implicitly disabling the
    // 'unsafe-inline' preference.

    policyObj['script-src'] = this.createPolicyObj(
      $,
      'script-src',
      'script:not([src])',
      policyObj,
      parsedUserPolicy
    );
    policyObj['style-src'] = this.createPolicyObj(
      $,
      'style-src',
      'style:not([href])',
      policyObj,
      parsedUserPolicy
    );

    metaTag.attr('content', this.buildPolicy(policyObj));

    // eslint-disable-next-line no-param-reassign
    htmlPluginData.html = $.html();

    return compileCb(null, htmlPluginData);
  }

  /**
   * Helper function for transforming script-src and style-src policies.
   * @param {object} $ - the Cheerio instance
   * @param {string} policyName - one of 'script-src' and 'style-src'
   * @param {string} selector - a Cheerio selector string for getting the hashable elements for this policy
   * @param {object} policyObj - the working CSP policy object
   * @param {object} userPolicyObj - the sanitized CSP policy object provided by the user
   * @return {object} the new policy for `policyName`
   */
  createPolicyObj($, policyName, selector, policyObj, userPolicyObj) {
    // Wrapped in flatten([]) to handle both when policy is a string and an array
    const flattenedUserPolicy = flatten(userPolicyObj[policyName]);
    if (flattenedUserPolicy.includes("'unsafe-inline'")) {
      return userPolicyObj[policyName];
    }

    const hashes = $(selector)
      .map((i, element) => this.hash($(element).html()))
      .get();
    return flatten([policyObj[policyName]]).concat(hashes);
  }

  /**
   * Hooks into webpack to collect assets and hash them, build the policy, and add it into our HTML template
   * @param compiler
   */
  apply(compiler) {
    if (compiler.hooks) {
      compiler.hooks.compilation.tap('CspHtmlWebpackPlugin', compilation => {
        // HtmlWebPackPlugin 3.x
        if (compilation.hooks.htmlWebpackPluginAfterHtmlProcessing) {
          compilation.hooks.htmlWebpackPluginAfterHtmlProcessing.tapAsync(
            'CspHtmlWebpackPlugin',
            this.processCsp.bind(this)
          );
        } else {
          // HtmlWebPackPlugin 4.x
          const HtmlWebpackPlugin = require('html-webpack-plugin'); // eslint-disable-line global-require
          HtmlWebpackPlugin.getHooks(compilation).beforeEmit.tapAsync(
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
