const fs = require('fs');
const path = require('path');
const cheerio = require('cheerio');
const webpack = require('webpack');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const rimraf = require('rimraf');
const CspHtmlWebpackPlugin = require('../plugin');

// Where we want to temporarily save files to
const OUTPUT_DIR = path.join(__dirname, '../dist');

/**
 * A wrapper to test all html output files
 * @param {object} webpackConfig - the webpack config to use when generating assets and HTML files
 * @param {string} outputFilename - what the html file we want to test is called
 * @param {function} callbackFn - the specific test function to run - it will be passed htmlContents as it's first
 *  param, and done as it's second. You must call done() at the end of the test
 * @param {function} doneFn - the jasmine done function to call in the callbackFn
 */
const testCspHtmlWebpackPlugin = (
  webpackConfig,
  outputFilename,
  callbackFn,
  doneFn
) => {
  webpack(webpackConfig, (err, stats) => {
    // test no error or warning
    expect(err).toBeFalsy();
    expect((stats.compilation.errors || []).length).toEqual(0);
    expect((stats.compilation.warnings || []).length).toEqual(0);

    // test the output file has been created
    const outputFileExists = fs.existsSync(
      path.join(OUTPUT_DIR, outputFilename)
    );
    expect(outputFileExists).toBe(true);
    if (!outputFileExists) {
      return doneFn();
    }

    // read html and pass into the callbackFn for testing
    const htmlContents = fs
      .readFileSync(path.join(OUTPUT_DIR, outputFilename))
      .toString();

    const $ = cheerio.load(htmlContents);
    const cspPolicy = $('meta[http-equiv="Content-Security-Policy"]').attr(
      'content'
    );

    return callbackFn(cspPolicy, doneFn);
  });
};

// Main list of tests
describe('CspHtmlWebpackPlugin', () => {
  beforeEach(done => {
    rimraf(OUTPUT_DIR, done);
  });

  afterAll(done => {
    rimraf(OUTPUT_DIR, done);
  });

  it('inserts the default policy, including sha-256 hashes of other scripts found', done => {
    const webpackConfig = {
      entry: path.join(__dirname, 'fixtures/index.js'),
      output: {
        path: OUTPUT_DIR,
        filename: 'index.bundle.js'
      },
      plugins: [
        new HtmlWebpackPlugin({
          filename: path.join(OUTPUT_DIR, 'index.html'),
          template: path.join(__dirname, 'fixtures', 'with-js.html'),
          inject: 'body'
        }),
        new CspHtmlWebpackPlugin()
      ]
    };

    testCspHtmlWebpackPlugin(
      webpackConfig,
      'index.html',
      (cspPolicy, doneFn) => {
        const expected =
          "base-uri 'self';" +
          " object-src 'none';" +
          " script-src 'unsafe-inline' 'self' 'unsafe-eval' 'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=' 'sha256-1/g1S+R6cGSDVKt1CRBpt3FqHB9xehMUo71n9mG7cQY=' 'sha256-S9NOMSwhoQnTw3XV3js7Vt906IHGcjM6CpUnE2ZtduM=';" +
          " style-src 'unsafe-inline' 'self' 'unsafe-eval'";

        expect(cspPolicy).toEqual(expected);

        doneFn();
      },
      done
    );
  });

  it('inserts the default policy, including sha-256 hashes of other styles found', done => {
    const webpackConfig = {
      entry: path.join(__dirname, 'fixtures/index.js'),
      output: {
        path: OUTPUT_DIR,
        filename: 'index.bundle.js'
      },
      plugins: [
        new HtmlWebpackPlugin({
          filename: path.join(OUTPUT_DIR, 'index.html'),
          template: path.join(__dirname, 'fixtures', 'with-css.html'),
          inject: 'body'
        }),
        new CspHtmlWebpackPlugin()
      ]
    };

    testCspHtmlWebpackPlugin(
      webpackConfig,
      'index.html',
      (cspPolicy, doneFn) => {
        const expected =
          "base-uri 'self';" +
          " object-src 'none';" +
          " script-src 'unsafe-inline' 'self' 'unsafe-eval' 'sha256-1/g1S+R6cGSDVKt1CRBpt3FqHB9xehMUo71n9mG7cQY=' 'sha256-S9NOMSwhoQnTw3XV3js7Vt906IHGcjM6CpUnE2ZtduM=';" +
          " style-src 'unsafe-inline' 'self' 'unsafe-eval' 'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU='";

        expect(cspPolicy).toEqual(expected);

        doneFn();
      },
      done
    );
  });

  it('inserts a custom policy if one is defined', done => {
    const webpackConfig = {
      entry: path.join(__dirname, 'fixtures/index.js'),
      output: {
        path: OUTPUT_DIR,
        filename: 'index.bundle.js'
      },
      plugins: [
        new HtmlWebpackPlugin({
          filename: path.join(OUTPUT_DIR, 'index.html'),
          template: path.join(__dirname, 'fixtures', 'with-nothing.html'),
          inject: 'body'
        }),
        new CspHtmlWebpackPlugin({
          'base-uri': ["'self'", 'https://slack.com'],
          'font-src': ["'self'", "'https://a-slack-edge.com'"],
          'script-src': ["'self'"],
          'style-src': ["'self'"]
        })
      ]
    };

    testCspHtmlWebpackPlugin(
      webpackConfig,
      'index.html',
      (cspPolicy, doneFn) => {
        const expected =
          "base-uri 'self' https://slack.com;" +
          " object-src 'none';" +
          " script-src 'self' 'sha256-1/g1S+R6cGSDVKt1CRBpt3FqHB9xehMUo71n9mG7cQY=' 'sha256-S9NOMSwhoQnTw3XV3js7Vt906IHGcjM6CpUnE2ZtduM=';" +
          " style-src 'self'; font-src 'self' 'https://a-slack-edge.com'";

        expect(cspPolicy).toEqual(expected);

        doneFn();
      },
      done
    );
  });

  it('ignores chunks which are not matched by the regex in the html webpack plugin settings', done => {
    const webpackConfig = {
      entry: {
        application: path.join(__dirname, 'fixtures/index.js'),
        ignored: path.join(__dirname, 'fixtures/ignored-index.js')
      },
      output: {
        path: OUTPUT_DIR,
        filename: '[name].[chunkhash:7].bundle.js'
      },
      plugins: [
        new HtmlWebpackPlugin({
          cspAssetRegex: /application/,
          filename: path.join(OUTPUT_DIR, 'index.html'),
          template: path.join(__dirname, 'fixtures', 'with-nothing.html'),
          inject: 'body'
        }),
        new CspHtmlWebpackPlugin()
      ]
    };

    testCspHtmlWebpackPlugin(
      webpackConfig,
      'index.html',
      (cspPolicy, doneFn) => {
        const expected =
          "base-uri 'self';" +
          " object-src 'none';" +
          " script-src 'unsafe-inline' 'self' 'unsafe-eval' 'sha256-2uo1+jaLVcs3Is1wS2OdiUivFJq8Lpq3ety7xHM/aog=' 'sha256-wnL0JqTYMsHFvBi2ivtYlWstb/A6bHBPrMG+iws3vRo=';" +
          " style-src 'unsafe-inline' 'self' 'unsafe-eval'";

        expect(cspPolicy).toEqual(expected);

        doneFn();
      },
      done
    );
  });

  it('matches chunks using the regex in the html webpack plugin settings which are in separate entry points', done => {
    const webpackConfig = {
      entry: {
        application: path.join(__dirname, 'fixtures/index.js'),
        ignored: path.join(__dirname, 'fixtures/ignored-index.js')
      },
      output: {
        path: OUTPUT_DIR,
        filename: '[name].[chunkhash:7].bundle.js'
      },
      plugins: [
        new HtmlWebpackPlugin({
          cspAssetRegex: /application|ignored/,
          filename: path.join(OUTPUT_DIR, 'index.html'),
          template: path.join(__dirname, 'fixtures', 'with-nothing.html'),
          inject: 'body'
        }),
        new CspHtmlWebpackPlugin()
      ]
    };

    testCspHtmlWebpackPlugin(
      webpackConfig,
      'index.html',
      (cspPolicy, doneFn) => {
        const expected =
          "base-uri 'self';" +
          " object-src 'none';" +
          " script-src 'unsafe-inline' 'self' 'unsafe-eval' 'sha256-2uo1+jaLVcs3Is1wS2OdiUivFJq8Lpq3ety7xHM/aog=' 'sha256-wnL0JqTYMsHFvBi2ivtYlWstb/A6bHBPrMG+iws3vRo=' 'sha256-WtMoz0By3R+9pniLse9vDKgXC8DQG2I3GDXk+TPNdH8=';" +
          " style-src 'unsafe-inline' 'self' 'unsafe-eval'";

        expect(cspPolicy).toEqual(expected);

        doneFn();
      },
      done
    );
  });
});
