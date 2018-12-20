const path = require('path');
const webpack = require('webpack');
const MemoryFs = require('memory-fs');
const cheerio = require('cheerio');

const WEBPACK_OUTPUT_DIR = path.join(__dirname, 'dist');

/**
 * Helper function for running a webpack compilation
 * @param {object} webpackConfig - the full webpack config to run
 * @param {function} callbackFn - the function to call when the compilation completes
 * @param {object} [fs] - the filesystem to build webpack into
 */
function webpackCompile(webpackConfig, callbackFn, { fs = null } = {}) {
  const instance = webpack(webpackConfig);

  const fileSystem = fs || new MemoryFs();
  instance.outputFileSystem = fileSystem;
  instance.run((err, stats) => {
    // test no error or warning
    expect(err).toBeFalsy();
    expect(stats.compilation.errors.length).toEqual(0);
    expect(stats.compilation.warnings.length).toEqual(0);

    // file all html files and convert them into cheerio objects so they can be queried
    const htmlFilesCheerio = fileSystem
      .readdirSync(WEBPACK_OUTPUT_DIR)
      .filter(file => file.endsWith('.html'))
      .reduce(
        (obj, file) => ({
          ...obj,
          [file]: cheerio.load(
            fileSystem
              .readFileSync(path.join(WEBPACK_OUTPUT_DIR, file))
              .toString()
          )
        }),
        {}
      );

    // find all csps from the cheerio objects
    const csps = Object.keys(htmlFilesCheerio).reduce((obj, file) => {
      const $ = htmlFilesCheerio[file];
      return {
        ...obj,
        [file]: $('meta[http-equiv="Content-Security-Policy"]').attr('content')
      };
    }, {});

    callbackFn(csps, htmlFilesCheerio, fileSystem);
  });
}

function createWebpackConfig(plugins) {
  return {
    mode: 'none',
    entry: path.join(__dirname, '..', 'spec', 'fixtures', 'index.js'),
    output: {
      path: WEBPACK_OUTPUT_DIR,
      filename: 'index.bundle.js'
    },
    plugins
  };
}

module.exports = {
  WEBPACK_OUTPUT_DIR,
  webpackCompile,
  createWebpackConfig
};
