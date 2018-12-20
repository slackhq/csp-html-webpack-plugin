const path = require('path');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const {
  WEBPACK_OUTPUT_DIR,
  createWebpackConfig,
  webpackCompile
} = require('./test-utils/webpack-helpers');
const CspHtmlWebpackPlugin = require('./plugin');

describe('CspHtmlWebpackPlugin', () => {
  describe('Error checking', () => {
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
  });

  describe('Adding sha checksums', () => {
    it('inserts the default policy, including sha-256 hashes of other inline scripts and styles found', done => {
      const config = createWebpackConfig([
        new HtmlWebpackPlugin({
          filename: path.join(WEBPACK_OUTPUT_DIR, 'index.html'),
          template: path.join(
            __dirname,
            'test-utils',
            'fixtures',
            'with-script-and-style.html'
          )
        }),
        new CspHtmlWebpackPlugin()
      ]);

      webpackCompile(config, csps => {
        const expected =
          "base-uri 'self';" +
          " object-src 'none';" +
          " script-src 'unsafe-inline' 'self' 'unsafe-eval' 'sha256-ixjZMYNfWQWawUHioWOx2jBsTmfxucX7IlwsMt2jWvc=';" +
          " style-src 'unsafe-inline' 'self' 'unsafe-eval' 'sha256-MqG77yUiqBo4MMVZAl09WSafnQY4Uu3cSdZPKxaf9sQ='";

        expect(csps['index.html']).toEqual(expected);
        done();
      });
    });

    it('inserts a custom policy if one is defined', done => {
      const config = createWebpackConfig([
        new HtmlWebpackPlugin({
          filename: path.join(WEBPACK_OUTPUT_DIR, 'index.html'),
          template: path.join(
            __dirname,
            'test-utils',
            'fixtures',
            'with-nothing.html'
          )
        }),
        new CspHtmlWebpackPlugin({
          'base-uri': ["'self'", 'https://slack.com'],
          'font-src': ["'self'", "'https://a-slack-edge.com'"],
          'script-src': ["'self'"],
          'style-src': ["'self'"],
          'connect-src': ["'self'"]
        })
      ]);

      webpackCompile(config, csps => {
        const expected =
          "base-uri 'self' https://slack.com;" +
          " object-src 'none';" +
          " script-src 'self';" +
          " style-src 'self';" +
          " font-src 'self' 'https://a-slack-edge.com';" +
          " connect-src 'self'";

        expect(csps['index.html']).toEqual(expected);
        done();
      });
    });

    it('handles string values for policies where the hash is appended', done => {
      const config = createWebpackConfig([
        new HtmlWebpackPlugin({
          filename: path.join(WEBPACK_OUTPUT_DIR, 'index.html'),
          template: path.join(
            __dirname,
            'test-utils',
            'fixtures',
            'with-script-and-style.html'
          )
        }),
        new CspHtmlWebpackPlugin({
          'script-src': "'self'",
          'style-src': "'self'"
        })
      ]);

      webpackCompile(config, csps => {
        const expected =
          "base-uri 'self';" +
          " object-src 'none';" +
          " script-src 'self' 'sha256-ixjZMYNfWQWawUHioWOx2jBsTmfxucX7IlwsMt2jWvc=';" +
          " style-src 'self' 'sha256-MqG77yUiqBo4MMVZAl09WSafnQY4Uu3cSdZPKxaf9sQ='";

        expect(csps['index.html']).toEqual(expected);
        done();
      });
    });

    describe('unsafe-inline / unsafe-eval', () => {
      it('skips the hashing of the scripts and styles it finds if devAllowUnsafe is true', done => {
        const config = createWebpackConfig([
          new HtmlWebpackPlugin({
            filename: path.join(WEBPACK_OUTPUT_DIR, 'index.html'),
            template: path.join(
              __dirname,
              'test-utils',
              'fixtures',
              'with-script-and-style.html'
            )
          }),
          new CspHtmlWebpackPlugin(
            {
              'base-uri': ["'self'", 'https://slack.com'],
              'font-src': ["'self'", "'https://a-slack-edge.com'"],
              'script-src': ["'self'", "'unsafe-inline'"],
              'style-src': ["'self'", "'unsafe-eval'"]
            },
            {
              devAllowUnsafe: true
            }
          )
        ]);

        webpackCompile(config, csps => {
          const expected =
            "base-uri 'self' https://slack.com;" +
            " object-src 'none';" +
            " script-src 'self' 'unsafe-inline';" +
            " style-src 'self' 'unsafe-eval';" +
            " font-src 'self' 'https://a-slack-edge.com'";

          expect(csps['index.html']).toEqual(expected);
          done();
        });
      });

      it('continues hashing scripts and styles if unsafe-inline/unsafe-eval is included, but devAllowUnsafe is false', done => {
        const config = createWebpackConfig([
          new HtmlWebpackPlugin({
            filename: path.join(WEBPACK_OUTPUT_DIR, 'index.html'),
            template: path.join(
              __dirname,
              'test-utils',
              'fixtures',
              'with-script-and-style.html'
            )
          }),
          new CspHtmlWebpackPlugin(
            {
              'base-uri': ["'self'", 'https://slack.com'],
              'font-src': ["'self'", "'https://a-slack-edge.com'"],
              'script-src': ["'self'", "'unsafe-inline'"],
              'style-src': ["'self'", "'unsafe-eval'"]
            },
            {
              devAllowUnsafe: false
            }
          )
        ]);

        webpackCompile(config, csps => {
          const expected =
            "base-uri 'self' https://slack.com;" +
            " object-src 'none';" +
            " script-src 'self' 'unsafe-inline' 'sha256-ixjZMYNfWQWawUHioWOx2jBsTmfxucX7IlwsMt2jWvc=';" +
            " style-src 'self' 'unsafe-eval' 'sha256-MqG77yUiqBo4MMVZAl09WSafnQY4Uu3cSdZPKxaf9sQ=';" +
            " font-src 'self' 'https://a-slack-edge.com'";

          expect(csps['index.html']).toEqual(expected);
          done();
        });
      });
    });
  });

  describe('Enabled check', () => {
    it('removes the empty Content Security Policy meta tag if enabled is the bool false', done => {
      const config = createWebpackConfig([
        new HtmlWebpackPlugin({
          filename: path.join(WEBPACK_OUTPUT_DIR, 'index.html'),
          template: path.join(
            __dirname,
            'test-utils',
            'fixtures',
            'with-nothing.html'
          )
        }),
        new CspHtmlWebpackPlugin(
          {},
          {
            enabled: false
          }
        )
      ]);

      webpackCompile(config, (csps, selectors) => {
        expect(csps['index.html']).toBeUndefined();
        expect(selectors['index.html']('meta').length).toEqual(1);
        done();
      });
    });

    it('removes the empty Content Security Policy meta tag if the `cspPlugin.disabled` option in HtmlWebpack Plugin is true', done => {
      const config = createWebpackConfig([
        new HtmlWebpackPlugin({
          filename: path.join(WEBPACK_OUTPUT_DIR, 'index.html'),
          template: path.join(
            __dirname,
            'test-utils',
            'fixtures',
            'with-nothing.html'
          ),
          cspPlugin: {
            enabled: false
          }
        }),
        new CspHtmlWebpackPlugin()
      ]);

      webpackCompile(config, (csps, selectors) => {
        expect(csps['index.html']).toBeUndefined();
        expect(selectors['index.html']('meta').length).toEqual(1);
        done();
      });
    });

    it('removes the empty Content Security Policy meta tag if enabled is a function which return false', done => {
      const config = createWebpackConfig([
        new HtmlWebpackPlugin({
          filename: path.join(WEBPACK_OUTPUT_DIR, 'index.html'),
          template: path.join(
            __dirname,
            'test-utils',
            'fixtures',
            'with-nothing.html'
          )
        }),
        new CspHtmlWebpackPlugin(
          {},
          {
            enabled: () => false
          }
        )
      ]);

      webpackCompile(config, (csps, selectors) => {
        expect(csps['index.html']).toBeUndefined();
        expect(selectors['index.html']('meta').length).toEqual(1);
        done();
      });
    });
  });

  describe('Meta tag', () => {
    it('still adds the CSP policy into the CSP meta tag even if the content attribute is missing', done => {
      const config = createWebpackConfig([
        new HtmlWebpackPlugin({
          filename: path.join(WEBPACK_OUTPUT_DIR, 'index.html'),
          template: path.join(
            __dirname,
            'test-utils',
            'fixtures',
            'with-no-content-attr.html'
          )
        }),
        new CspHtmlWebpackPlugin()
      ]);

      webpackCompile(config, csps => {
        const expected =
          "base-uri 'self';" +
          " object-src 'none';" +
          " script-src 'unsafe-inline' 'self' 'unsafe-eval';" +
          " style-src 'unsafe-inline' 'self' 'unsafe-eval'";

        expect(csps['index.html']).toEqual(expected);
        done();
      });
    });

    it('adds meta tag with completed policy when no meta tag is specified', done => {
      const config = createWebpackConfig([
        new HtmlWebpackPlugin({
          filename: path.join(WEBPACK_OUTPUT_DIR, 'index.html'),
          template: path.join(
            __dirname,
            'test-utils',
            'fixtures',
            'with-no-meta-tag.html'
          )
        }),
        new CspHtmlWebpackPlugin()
      ]);

      webpackCompile(config, csps => {
        const expected =
          "base-uri 'self';" +
          " object-src 'none';" +
          " script-src 'unsafe-inline' 'self' 'unsafe-eval';" +
          " style-src 'unsafe-inline' 'self' 'unsafe-eval'";

        expect(csps['index.html']).toEqual(expected);
        done();
      });
    });

    it('adds meta tag with completed policy when no template is specified', done => {
      const config = createWebpackConfig([
        new HtmlWebpackPlugin({
          filename: path.join(WEBPACK_OUTPUT_DIR, 'index.html')
        }),
        new CspHtmlWebpackPlugin()
      ]);

      webpackCompile(config, csps => {
        const expected =
          "base-uri 'self';" +
          " object-src 'none';" +
          " script-src 'unsafe-inline' 'self' 'unsafe-eval';" +
          " style-src 'unsafe-inline' 'self' 'unsafe-eval'";

        expect(csps['index.html']).toEqual(expected);
        done();
      });
    });

    it("adds the meta tag as the top most meta tag to ensure that the CSP is defined before we try loading any other scripts, if it doesn't exist", done => {
      const config = createWebpackConfig([
        new HtmlWebpackPlugin({
          filename: path.join(WEBPACK_OUTPUT_DIR, 'index.html'),
          template: path.join(
            __dirname,
            'test-utils',
            'fixtures',
            'with-script-and-style.html'
          )
        }),
        new CspHtmlWebpackPlugin()
      ]);

      webpackCompile(config, (csps, selectors) => {
        const $ = selectors['index.html'];
        const metaTags = $('meta');

        expect(metaTags[0].attribs['http-equiv']).toEqual(
          'Content-Security-Policy'
        );

        done();
      });
    });
  });
});
