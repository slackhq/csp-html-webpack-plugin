const cheerio = require('cheerio');
const crypto = require('crypto');
const uniq = require('lodash/uniq');
const compact = require('lodash/compact');
const keyBy = require('lodash/keyBy');

const defaultPolicy = {
  'base-uri': "'self'",
  'object-src': "'none'",
  'script-src': ["'unsafe-inline'", "'self'", "'unsafe-eval'"],
  'style-src': ["'unsafe-inline'", "'self'", "'unsafe-eval'"]
};

const defaultAdditionalOpts = {
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

    // the additional options that this plugin allows
    this.opts = Object.assign({}, defaultAdditionalOpts, additionalOpts);

    // a store of all the js and css hashes we find
    this.hashes = {
      js: [],
      css: []
    };

    // valid hashes from https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy/script-src#Sources
    if (!['sha256', 'sha384', 'sha512'].includes(this.opts.hashingMethod)) {
      throw new Error(
        `'${this.opts.hashingMethod}' is not a valid hashing method`
      );
    }
  }

  /**
   * Gets the file type from a string
   * @param str - the string name of the file to determine the file type of e.g. application.12345.js
   * @returns {string|null} the file type e.g. js
   */
  // eslint-disable-next-line class-methods-use-this
  getFileType(str) {
    if (!str.includes('.')) {
      return null;
    }

    const parts = str.replace(/\?.*/, '').split('.');

    return parts.pop();
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
   * Find the asset source using the filename we pass in and adds it to the hashes array under the appropriate key
   * @param {string} filename - the filename to search for in the assets object
   * @param {object} assets - the assets object from compilation.assets
   */
  addToHashesArray(filename, assets) {
    const fileType = this.getFileType(filename);
    const assetSource = assets[filename] && assets[filename].source();

    if (assetSource && ['js', 'css'].includes(fileType)) {
      this.hashes[fileType].push(this.hash(assetSource));
    }
  }

  /**
   * Process assets and it's children which match the cspAssetRegex option
   * @param {RegExp} regex the regex to test the filenames for
   * @param {object[]} statsJsonChunks - compilation.getStats().toJson().chunks
   * @param compilationAssets - compilation.assets
   */
  processLimited(regex, statsJsonChunks, compilationAssets) {
    const keyedChunksById = keyBy(statsJsonChunks, o => o.id);
    const parentChildChunkRelationship = {};
    const matchedChunkIds = [];
    const seenChunkId = [];

    let manifestChunkId = -1;

    statsJsonChunks.forEach(chunk => {
      if (typeof chunk.id !== 'undefined') {
        // add all chunks into a parent child map
        for (let i = 0, len = chunk.parents.length; i < len; i += 1) {
          const parent = chunk.parents[i];
          if (!parentChildChunkRelationship[parent]) {
            parentChildChunkRelationship[parent] = [chunk.id.toString()];
          } else {
            parentChildChunkRelationship[parent].push(chunk.id.toString());
          }
        }

        // if the chunk size is 0 right now, it's probably the empty manifest chunk - let's mark it as such
        if (chunk.size === 0) {
          manifestChunkId = chunk.id;
        }

        // match filenames we want to hash
        for (let i = 0, len = chunk.files.length; i < len; i += 1) {
          if (regex.test(chunk.files[i])) {
            matchedChunkIds.push(chunk.id);
            return;
          }
        }
      }
    });

    // recursive function to go through all chunk children and hash their sources too
    const processChunkId = chunkId => {
      // make sure we don't get into an infinite loop
      if (seenChunkId.includes(chunkId)) {
        return;
      }

      const chunk = keyedChunksById[chunkId];
      chunk.files.forEach(filename => {
        this.addToHashesArray(filename, compilationAssets);
      });

      // if we have children to iterate, and we're not currently on the manifest chunk, iterate through them
      if (
        typeof parentChildChunkRelationship[chunkId] !== 'undefined' &&
        parentChildChunkRelationship[chunkId].length > 0 &&
        chunkId !== manifestChunkId
      ) {
        for (
          let i = 0, len = parentChildChunkRelationship[chunkId].length;
          i < len;
          i += 1
        ) {
          processChunkId(parentChildChunkRelationship[chunkId][i]);
        }
      }
    };

    // start the hashing
    matchedChunkIds.forEach(chunkId => {
      processChunkId(chunkId);
    });
  }

  /**
   * Process all assets since no cspAssetRegex has been set
   * @param {object[]} statsJsonAssets - compilation.getStats().toJson().assets
   * @param compilationAssets - compilation.assets
   */
  processAll(statsJsonAssets, compilationAssets) {
    statsJsonAssets.forEach(asset => {
      this.addToHashesArray(asset.name, compilationAssets);
    });
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
   * Hooks into webpack to collect assets and hash them, build the policy, and add it into our HTML template
   * @param compiler
   */
  apply(compiler) {
    compiler.plugin('compilation', compilation => {
      compilation.plugin(
        'html-webpack-plugin-after-html-processing',
        (htmlPluginData, compileCb) => {
          const stats = compilation.getStats().toJson();
          const { assets } = compilation; // only way to get source

          if (!htmlPluginData.plugin.options.cspAssetRegex) {
            this.processAll(stats.assets, assets);
          } else {
            this.processLimited(
              htmlPluginData.plugin.options.cspAssetRegex,
              stats.chunks,
              assets
            );
          }

          const $ = cheerio.load(htmlPluginData.html);
          const policyObj = JSON.parse(JSON.stringify(this.policy));

          const inlineScripts = $('script:not([src])')
            .map((i, element) => this.hash($(element).text()))
            .get();
          const inlineStyle = $('style:not([href])')
            .map((i, element) => this.hash($(element).text()))
            .get();

          policyObj['script-src'] = policyObj['script-src'].concat(
            inlineScripts,
            this.hashes.js
          );
          policyObj['style-src'] = policyObj['style-src'].concat(
            inlineStyle,
            this.hashes.css
          );

          // eslint-disable-next-line no-param-reassign
          htmlPluginData.html = htmlPluginData.html.replace(
            '%%CSP_POLICY%%',
            this.buildPolicy(policyObj)
          );

          compileCb(null, htmlPluginData);
        }
      );
    });
  }
}

module.exports = CspHtmlWebpackPlugin;
