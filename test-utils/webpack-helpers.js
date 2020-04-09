const path = require('path');
const webpack = require('webpack');
const MemoryFs = require('memory-fs');
const cheerio = require('cheerio');

/**
 * Where we want to output our files in the memory filesystem
 * @type {string}
 */
const WEBPACK_OUTPUT_DIR = path.join(__dirname, 'dist');

/**
 * Helper function for running a webpack compilation
 * @param {object} webpackConfig - the full webpack config to run
 * @param {function} callbackFn - the function to call when the compilation completes
 * @param {object} [fs] - the filesystem to build webpack into
 * @param {boolean} expectError - whether we expect an error from webpack - if so, pass it through
 */
function webpackCompile(
  webpackConfig,
  callbackFn,
  { fs = null, expectError = false } = {}
) {
  const instance = webpack(webpackConfig);

  const fileSystem = fs || new MemoryFs();
  instance.outputFileSystem = fileSystem;
  instance.run((err, stats) => {
    // test no error or warning
    if (!expectError) {
      expect(err).toBeFalsy();
      expect(stats.compilation.errors.length).toEqual(0);
      expect(stats.compilation.warnings.length).toEqual(0);
    }

    // file all html files and convert them into cheerio objects so they can be queried
    const htmlFilesCheerio = fileSystem
      .readdirSync(WEBPACK_OUTPUT_DIR)
      .filter((file) => file.endsWith('.html'))
      .reduce(
        (obj, file) => ({
          ...obj,
          [file]: cheerio.load(
            fileSystem
              .readFileSync(path.join(WEBPACK_OUTPUT_DIR, file))
              .toString()
          ),
        }),
        {}
      );

    // find all csps from the cheerio objects
    const csps = Object.keys(htmlFilesCheerio).reduce((obj, file) => {
      const $ = htmlFilesCheerio[file];
      return {
        ...obj,
        [file]: $('meta[http-equiv="Content-Security-Policy"]').attr('content'),
      };
    }, {});

    callbackFn(
      csps,
      htmlFilesCheerio,
      fileSystem,
      stats.compilation.errors,
      stats.compilation.warnings
    );
  });
}

/**
 * Helper to create a basic webpack config which can then be used in the compile function
 * @param plugins[] - array of plugins to pass into webpack
 * @param {string} publicPath - publicPath setting for webpack
 * @return {{mode: string, output: {path: string, filename: string}, entry: string, plugins: *}}
 */
function createWebpackConfig(plugins, publicPath = undefined) {
  return {
    mode: 'none',
    entry: path.join(__dirname, '..', 'test-utils', 'fixtures', 'index.js'),
    output: {
      path: WEBPACK_OUTPUT_DIR,
      publicPath,
      filename: 'index.bundle.js',
    },
    plugins,
  };
}

module.exports = {
  WEBPACK_OUTPUT_DIR,
  webpackCompile,
  createWebpackConfig,
};
