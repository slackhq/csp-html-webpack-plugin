const path = require('path');
const crypto = require('crypto');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const {
  WEBPACK_OUTPUT_DIR,
  createWebpackConfig,
  webpackCompile
} = require('./test-utils/webpack-helpers');
const CspHtmlWebpackPlugin = require('./plugin');

describe('CspHtmlWebpackPlugin', () => {
  beforeEach(() => {
    jest
      .spyOn(crypto, 'randomBytes')
      .mockImplementationOnce(() => 'mockedbase64string-1')
      .mockImplementationOnce(() => 'mockedbase64string-2')
      .mockImplementationOnce(() => 'mockedbase64string-3')
      .mockImplementation(
        () => new Error('Need to add more crypto.randomBytes mocks')
      );
  });

  afterEach(() => {
    crypto.randomBytes.mockReset();
  });

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

    describe('validatePolicy', () => {
      [
        'self',
        'unsafe-inline',
        'unsafe-eval',
        'none',
        'strict-dynamic',
        'report-sample'
      ].forEach(source => {
        it(`throws an error if '${source}' is not wrapped in apostrophes in an array defined policy`, done => {
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
              'script-src': [source]
            })
          ]);

          webpackCompile(
            config,
            (_1, _2, _3, errors) => {
              expect(errors[0]).toEqual(
                new Error(
                  `CSP: policy for script-src contains ${source} which should be wrapped in apostrophes`
                )
              );
              done();
            },
            {
              expectError: true
            }
          );
        });

        it(`throws an error if '${source}' is not wrapped in apostrophes in a string defined policy`, done => {
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
              'script-src': source
            })
          ]);

          webpackCompile(
            config,
            (_1, _2, _3, errors) => {
              expect(errors[0]).toEqual(
                new Error(
                  `CSP: policy for script-src contains ${source} which should be wrapped in apostrophes`
                )
              );
              done();
            },
            {
              expectError: true
            }
          );
        });
      });
    });
  });

  describe('Adding sha and nonce checksums', () => {
    it('inserts the default policy, including sha-256 hashes of other inline scripts and styles found, and nonce hashes of external scripts found', done => {
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
          " script-src 'unsafe-inline' 'self' 'unsafe-eval' 'sha256-ixjZMYNfWQWawUHioWOx2jBsTmfxucX7IlwsMt2jWvc=' 'nonce-mockedbase64string-1' 'nonce-mockedbase64string-2';" +
          " style-src 'unsafe-inline' 'self' 'unsafe-eval' 'sha256-MqG77yUiqBo4MMVZAl09WSafnQY4Uu3cSdZPKxaf9sQ=' 'nonce-mockedbase64string-3'";

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
          " script-src 'self' 'nonce-mockedbase64string-1';" +
          " style-src 'self';" +
          " font-src 'self' 'https://a-slack-edge.com';" +
          " connect-src 'self'";

        expect(csps['index.html']).toEqual(expected);
        done();
      });
    });

    it('handles string values for policies where hashes and nonces are appended', done => {
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
          " script-src 'self' 'sha256-ixjZMYNfWQWawUHioWOx2jBsTmfxucX7IlwsMt2jWvc=' 'nonce-mockedbase64string-1' 'nonce-mockedbase64string-2';" +
          " style-src 'self' 'sha256-MqG77yUiqBo4MMVZAl09WSafnQY4Uu3cSdZPKxaf9sQ=' 'nonce-mockedbase64string-3'";

        expect(csps['index.html']).toEqual(expected);
        done();
      });
    });

    it("doesn't add nonces for scripts / styles generated where their host has already been defined in the CSP, and 'strict-dynamic' doesn't exist in the policy", done => {
      const config = createWebpackConfig(
        [
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
            'script-src': ["'self'", 'https://my.cdn.com'],
            'style-src': ["'self'"]
          })
        ],
        'https://my.cdn.com/'
      );

      webpackCompile(config, (csps, selectors) => {
        const $ = selectors['index.html'];
        const expected =
          "base-uri 'self';" +
          " object-src 'none';" +
          " script-src 'self' https://my.cdn.com 'sha256-ixjZMYNfWQWawUHioWOx2jBsTmfxucX7IlwsMt2jWvc=' 'nonce-mockedbase64string-1';" +
          " style-src 'self' 'sha256-MqG77yUiqBo4MMVZAl09WSafnQY4Uu3cSdZPKxaf9sQ=' 'nonce-mockedbase64string-2'";

        // csp should be defined properly
        expect(csps['index.html']).toEqual(expected);

        // script with host not defined should have nonce defined, and correct
        expect($('script')[0].attribs.src).toEqual(
          'https://example.com/example.js'
        );
        expect($('script')[0].attribs.nonce).toEqual('mockedbase64string-1');

        // inline script, so no nonce
        expect($('script')[1].attribs).toEqual({});

        // script with host defined should not have a nonce
        expect($('script')[2].attribs.src).toEqual(
          'https://my.cdn.com/index.bundle.js'
        );
        expect(Object.keys($('script')[2].attribs)).not.toContain('nonce');

        done();
      });
    });

    it("continues to add nonces to scripts / styles even if the host has already been whitelisted due to 'strict-dynamic' existing in the policy", done => {
      const config = createWebpackConfig(
        [
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
            'script-src': ["'self'", "'strict-dynamic'", 'https://my.cdn.com'],
            'style-src': ["'self'"]
          })
        ],
        'https://my.cdn.com/'
      );

      webpackCompile(config, (csps, selectors) => {
        const $ = selectors['index.html'];

        // 'strict-dynamic' should be at the end of the script-src here
        const expected =
          "base-uri 'self';" +
          " object-src 'none';" +
          " script-src 'self' https://my.cdn.com 'sha256-ixjZMYNfWQWawUHioWOx2jBsTmfxucX7IlwsMt2jWvc=' 'nonce-mockedbase64string-1' 'nonce-mockedbase64string-2' 'strict-dynamic';" +
          " style-src 'self' 'sha256-MqG77yUiqBo4MMVZAl09WSafnQY4Uu3cSdZPKxaf9sQ=' 'nonce-mockedbase64string-3'";

        // csp should be defined properly
        expect(csps['index.html']).toEqual(expected);

        // script with host not defined should have nonce defined, and correct
        expect($('script')[0].attribs.src).toEqual(
          'https://example.com/example.js'
        );
        expect($('script')[0].attribs.nonce).toEqual('mockedbase64string-1');

        // inline script, so no nonce
        expect($('script')[1].attribs).toEqual({});

        // script with host defined should also have a nonce
        expect($('script')[2].attribs.src).toEqual(
          'https://my.cdn.com/index.bundle.js'
        );
        expect($('script')[2].attribs.nonce).toEqual('mockedbase64string-2');

        done();
      });
    });

    describe('HtmlWebpackPlugin defined policy', () => {
      it('inserts a custom policy from a specific HtmlWebpackPlugin instance, if one is defined', done => {
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
              policy: {
                'base-uri': ["'self'", 'https://slack.com'],
                'font-src': ["'self'", "'https://a-slack-edge.com'"],
                'script-src': ["'self'"],
                'style-src': ["'self'"],
                'connect-src': ["'self'"]
              }
            }
          }),
          new CspHtmlWebpackPlugin()
        ]);

        webpackCompile(config, csps => {
          const expected =
            "base-uri 'self' https://slack.com;" +
            " object-src 'none';" +
            " script-src 'self' 'nonce-mockedbase64string-1';" +
            " style-src 'self';" +
            " font-src 'self' 'https://a-slack-edge.com';" +
            " connect-src 'self'";

          expect(csps['index.html']).toEqual(expected);
          done();
        });
      });

      it('merges and overwrites policies, with a html webpack plugin instance policy taking precedence, followed by the csp instance, and then the default policy', done => {
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
              policy: {
                'font-src': [
                  "'https://a-slack-edge.com'",
                  "'https://b-slack-edge.com'"
                ]
              }
            }
          }),
          new CspHtmlWebpackPlugin({
            'base-uri': ["'self'", 'https://slack.com'],
            'font-src': ["'self'"]
          })
        ]);

        webpackCompile(config, csps => {
          const expected =
            "base-uri 'self' https://slack.com;" + // this should be included as it's not defined in the HtmlWebpackPlugin instance
            " object-src 'none';" + // this comes from the default policy
            " script-src 'unsafe-inline' 'self' 'unsafe-eval' 'nonce-mockedbase64string-1';" + // this comes from the default policy
            " style-src 'unsafe-inline' 'self' 'unsafe-eval';" + // this comes from the default policy
            " font-src 'https://a-slack-edge.com' 'https://b-slack-edge.com'"; // this should only include the HtmlWebpackPlugin instance policy

          expect(csps['index.html']).toEqual(expected);
          done();
        });
      });

      it('only adds a custom policy to the html file which has a policy defined; uses the default policy for any others', done => {
        const config = createWebpackConfig([
          new HtmlWebpackPlugin({
            filename: path.join(WEBPACK_OUTPUT_DIR, 'index-csp.html'),
            template: path.join(
              __dirname,
              'test-utils',
              'fixtures',
              'with-nothing.html'
            ),
            cspPlugin: {
              policy: {
                'script-src': ["'https://a-slack-edge.com'"],
                'style-src': ["'https://b-slack-edge.com'"]
              }
            }
          }),
          new HtmlWebpackPlugin({
            filename: path.join(WEBPACK_OUTPUT_DIR, 'index-no-csp.html'),
            template: path.join(
              __dirname,
              'test-utils',
              'fixtures',
              'with-nothing.html'
            )
          }),
          new CspHtmlWebpackPlugin()
        ]);

        webpackCompile(config, csps => {
          const expectedCustom =
            "base-uri 'self';" +
            " object-src 'none';" +
            " script-src 'https://a-slack-edge.com' 'nonce-mockedbase64string-1';" +
            " style-src 'https://b-slack-edge.com'";

          const expectedDefault =
            "base-uri 'self';" +
            " object-src 'none';" +
            " script-src 'unsafe-inline' 'self' 'unsafe-eval' 'nonce-mockedbase64string-2';" +
            " style-src 'unsafe-inline' 'self' 'unsafe-eval'";

          expect(csps['index-csp.html']).toEqual(expectedCustom);
          expect(csps['index-no-csp.html']).toEqual(expectedDefault);
          done();
        });
      });
    });

    describe('unsafe-inline / unsafe-eval', () => {
      it('skips the hashing / nonceing of the scripts and styles it finds if devAllowUnsafe is true', done => {
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

      it('continues hashing / nonceing scripts and styles if unsafe-inline/unsafe-eval is included, but devAllowUnsafe is false', done => {
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
            " script-src 'self' 'unsafe-inline' 'sha256-ixjZMYNfWQWawUHioWOx2jBsTmfxucX7IlwsMt2jWvc=' 'nonce-mockedbase64string-1' 'nonce-mockedbase64string-2';" +
            " style-src 'self' 'unsafe-eval' 'sha256-MqG77yUiqBo4MMVZAl09WSafnQY4Uu3cSdZPKxaf9sQ=' 'nonce-mockedbase64string-3';" +
            " font-src 'self' 'https://a-slack-edge.com'";

          expect(csps['index.html']).toEqual(expected);
          done();
        });
      });
    });
  });

  describe('Enabled check', () => {
    it("doesn't modify the html if enabled is the bool false", done => {
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

    it("doesn't modify the html if the `cspPlugin.enabled` option in HtmlWebpack Plugin is false", done => {
      const config = createWebpackConfig([
        new HtmlWebpackPlugin({
          filename: path.join(WEBPACK_OUTPUT_DIR, 'index.html'),
          template: path.join(
            __dirname,
            'test-utils',
            'fixtures',
            'with-no-meta-tag.html'
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

    it("doesn't modify the html if enabled is a function which return false", done => {
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

    it("doesn't modify html from the HtmlWebpackPlugin instance which has been disabled", done => {
      const config = createWebpackConfig([
        new HtmlWebpackPlugin({
          filename: path.join(WEBPACK_OUTPUT_DIR, 'index-enabled.html'),
          template: path.join(
            __dirname,
            'test-utils',
            'fixtures',
            'with-no-meta-tag.html'
          )
        }),
        new HtmlWebpackPlugin({
          filename: path.join(WEBPACK_OUTPUT_DIR, 'index-disabled.html'),
          template: path.join(
            __dirname,
            'test-utils',
            'fixtures',
            'with-no-meta-tag.html'
          ),
          cspPlugin: {
            enabled: false
          }
        }),
        new CspHtmlWebpackPlugin()
      ]);

      webpackCompile(config, (csps, selectors) => {
        expect(csps['index-enabled.html']).toBeDefined();
        expect(csps['index-disabled.html']).toBeUndefined();
        expect(selectors['index-enabled.html']('meta').length).toEqual(2);
        expect(selectors['index-disabled.html']('meta').length).toEqual(1);
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
          " script-src 'unsafe-inline' 'self' 'unsafe-eval' 'nonce-mockedbase64string-1';" +
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
          " script-src 'unsafe-inline' 'self' 'unsafe-eval' 'nonce-mockedbase64string-1';" +
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
          " script-src 'unsafe-inline' 'self' 'unsafe-eval' 'nonce-mockedbase64string-1';" +
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
