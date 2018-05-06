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
    expect(stats.compilation.errors.length).toEqual(0);
    expect(stats.compilation.warnings.length).toEqual(0);

    // test the output file has been created
    const outputFileExists = fs.existsSync(
      path.join(OUTPUT_DIR, outputFilename)
    );
    expect(outputFileExists).toBe(true);
    /* istanbul ignore next */
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

    return callbackFn(cspPolicy, $, doneFn);
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

  it('inserts the default policy, including sha-256 hashes of other inline scripts found', done => {
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
      (cspPolicy, _, doneFn) => {
        const expected =
          "base-uri 'self';" +
          " object-src 'none';" +
          " script-src 'unsafe-inline' 'self' 'unsafe-eval' 'sha256-9nPWXYBnlIeJ9HmieIATDv9Ab5plt35XZiT48TfEkJI=';" +
          " style-src 'unsafe-inline' 'self' 'unsafe-eval'";

        expect(cspPolicy).toEqual(expected);

        doneFn();
      },
      done
    );
  });

  it('inserts the default policy, including sha-256 hashes of other inline styles found', done => {
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
      (cspPolicy, _, doneFn) => {
        const expected =
          "base-uri 'self';" +
          " object-src 'none';" +
          " script-src 'unsafe-inline' 'self' 'unsafe-eval';" +
          " style-src 'unsafe-inline' 'self' 'unsafe-eval' 'sha256-MqG77yUiqBo4MMVZAl09WSafnQY4Uu3cSdZPKxaf9sQ='";

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
      (cspPolicy, _, doneFn) => {
        const expected =
          "base-uri 'self' https://slack.com;" +
          " object-src 'none';" +
          " script-src 'self';" +
          " style-src 'self';" +
          " font-src 'self' 'https://a-slack-edge.com'";

        expect(cspPolicy).toEqual(expected);

        doneFn();
      },
      done
    );
  });

  it('removes the empty Content Security Policy meta tag if enabled is the bool false', done => {
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
        new CspHtmlWebpackPlugin(
          {},
          {
            enabled: false
          }
        )
      ]
    };

    testCspHtmlWebpackPlugin(
      webpackConfig,
      'index.html',
      (cspPolicy, $, doneFn) => {
        expect(cspPolicy).toBeUndefined();
        expect($('meta').length).toEqual(1);
        doneFn();
      },
      done
    );
  });

  it('removes the empty Content Security Policy meta tag if enabled is a function which return false', done => {
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
        new CspHtmlWebpackPlugin(
          {},
          {
            enabled: () => false
          }
        )
      ]
    };

    testCspHtmlWebpackPlugin(
      webpackConfig,
      'index.html',
      (cspPolicy, $, doneFn) => {
        expect(cspPolicy).toBeUndefined();
        expect($('meta').length).toEqual(1);
        doneFn();
      },
      done
    );
  });

  it('still adds the CSP policy into the CSP meta tag even if the content attribute is missing', done => {
    const webpackConfig = {
      entry: path.join(__dirname, 'fixtures/index.js'),
      output: {
        path: OUTPUT_DIR,
        filename: 'index.bundle.js'
      },
      plugins: [
        new HtmlWebpackPlugin({
          filename: path.join(OUTPUT_DIR, 'index.html'),
          template: path.join(
            __dirname,
            'fixtures',
            'with-no-content-attr.html'
          ),
          inject: 'body'
        }),
        new CspHtmlWebpackPlugin({
          'base-uri': ["'self'", 'https://slack.com'],
          'object-src': ["'self'"],
          'script-src': ["'self'"],
          'style-src': ["'self'"]
        })
      ]
    };

    testCspHtmlWebpackPlugin(
      webpackConfig,
      'index.html',
      (cspPolicy, _, doneFn) => {
        const expected =
          "base-uri 'self' https://slack.com;" +
          " object-src 'self';" +
          " script-src 'self';" +
          " style-src 'self'";

        expect(cspPolicy).toEqual(expected);

        doneFn();
      },
      done
    );
  });

  it('adds meta tag when no template is specified', done => {
    const webpackConfig = {
      entry: path.join(__dirname, 'fixtures/index.js'),
      output: {
        path: OUTPUT_DIR,
        filename: 'index.bundle.js'
      },
      plugins: [
        new HtmlWebpackPlugin({
          filename: path.join(OUTPUT_DIR, 'index.html'),
          inject: 'body'
        }),
        new CspHtmlWebpackPlugin({
          'base-uri': ["'self'", 'https://slack.com'],
          'object-src': ["'self'"],
          'script-src': ["'self'"],
          'style-src': ["'self'"]
        })
      ]
    };

    testCspHtmlWebpackPlugin(
      webpackConfig,
      'index.html',
      (cspPolicy, _, doneFn) => {
        const expected =
          "base-uri 'self' https://slack.com;" +
          " object-src 'self';" +
          " script-src 'self';" +
          " style-src 'self'";

        expect(cspPolicy).toEqual(expected);

        doneFn();
      },
      done
    );
  });

  it('throws an error if an invalid hashing method is used', () => {
    expect(() => {
      // eslint-disable-next-line no-new
      new CspHtmlWebpackPlugin(
        {},
        {
          hashingMethod: 'invalid'
        }
      );
    }).toThrow(new Error(`'invalid' is not a valid hashing method`));
  });

  it('handles string values for policies where the hash is appended', done => {
    const webpackConfig = {
      entry: path.join(__dirname, 'fixtures/index.js'),
      output: { path: OUTPUT_DIR, filename: 'index.bundle.js' },
      plugins: [
        new HtmlWebpackPlugin({
          filename: path.join(OUTPUT_DIR, 'index.html'),
          template: path.join(__dirname, 'fixtures', 'with-js.html'),
          inject: 'body'
        }),
        new CspHtmlWebpackPlugin({
          'script-src': "'self'",
          'style-src': "'self'"
        })
      ]
    };

    testCspHtmlWebpackPlugin(
      webpackConfig,
      'index.html',
      (cspPolicy, _, doneFn) => {
        const expected =
          "base-uri 'self';" +
          " object-src 'none';" +
          " script-src 'self' 'sha256-9nPWXYBnlIeJ9HmieIATDv9Ab5plt35XZiT48TfEkJI=';" +
          " style-src 'self'";

        expect(cspPolicy).toEqual(expected);

        doneFn();
      },
      done
    );
  });
});
