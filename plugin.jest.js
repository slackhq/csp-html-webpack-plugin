const path = require('path');
const crypto = require('crypto');
const HtmlWebpackPlugin = require('html-webpack-plugin');
const { RawSource } = require('webpack-sources');
const {
  WEBPACK_OUTPUT_DIR,
  createWebpackConfig,
  webpackCompile,
} = require('./test-utils/webpack-helpers');
const CspHtmlWebpackPlugin = require('./plugin');

describe('CspHtmlWebpackPlugin', () => {
  beforeEach(() => {
    jest
      .spyOn(crypto, 'randomBytes')
      .mockImplementationOnce(() => 'mockedbase64string-1')
      .mockImplementationOnce(() => 'mockedbase64string-2')
      .mockImplementationOnce(() => 'mockedbase64string-3')
      .mockImplementationOnce(() => 'mockedbase64string-4')
      .mockImplementationOnce(() => 'mockedbase64string-5')
      .mockImplementationOnce(() => 'mockedbase64string-6')
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
            hashingMethod: 'invalid',
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
        'report-sample',
      ].forEach((source) => {
        it(`throws an error if '${source}' is not wrapped in apostrophes in an array defined policy`, (done) => {
          const config = createWebpackConfig([
            new HtmlWebpackPlugin({
              filename: path.join(WEBPACK_OUTPUT_DIR, 'index.html'),
              template: path.join(
                __dirname,
                'test-utils',
                'fixtures',
                'with-nothing.html'
              ),
            }),
            new CspHtmlWebpackPlugin({
              'script-src': [source],
            }),
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
              expectError: true,
            }
          );
        });

        it(`throws an error if '${source}' is not wrapped in apostrophes in a string defined policy`, (done) => {
          const config = createWebpackConfig([
            new HtmlWebpackPlugin({
              filename: path.join(WEBPACK_OUTPUT_DIR, 'index.html'),
              template: path.join(
                __dirname,
                'test-utils',
                'fixtures',
                'with-nothing.html'
              ),
            }),
            new CspHtmlWebpackPlugin({
              'script-src': source,
            }),
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
              expectError: true,
            }
          );
        });
      });
    });
  });

  describe('Adding sha and nonce checksums', () => {
    it('inserts the default policy, including sha-256 hashes of other inline scripts and styles found, and nonce hashes of external scripts found', (done) => {
      const config = createWebpackConfig([
        new HtmlWebpackPlugin({
          filename: path.join(WEBPACK_OUTPUT_DIR, 'index.html'),
          template: path.join(
            __dirname,
            'test-utils',
            'fixtures',
            'with-script-and-style.html'
          ),
        }),
        new CspHtmlWebpackPlugin(),
      ]);

      webpackCompile(config, (csps) => {
        const expected =
          "base-uri 'self';" +
          " object-src 'none';" +
          " script-src 'unsafe-inline' 'self' 'unsafe-eval' 'sha256-ixjZMYNfWQWawUHioWOx2jBsTmfxucX7IlwsMt2jWvc=' 'nonce-mockedbase64string-1' 'nonce-mockedbase64string-2';" +
          " style-src 'unsafe-inline' 'self' 'unsafe-eval' 'sha256-MqG77yUiqBo4MMVZAl09WSafnQY4Uu3cSdZPKxaf9sQ=' 'nonce-mockedbase64string-3'";

        expect(csps['index.html']).toEqual(expected);
        done();
      });
    });

    it('inserts a custom policy if one is defined', (done) => {
      const config = createWebpackConfig([
        new HtmlWebpackPlugin({
          filename: path.join(WEBPACK_OUTPUT_DIR, 'index.html'),
          template: path.join(
            __dirname,
            'test-utils',
            'fixtures',
            'with-nothing.html'
          ),
        }),
        new CspHtmlWebpackPlugin({
          'base-uri': ["'self'", 'https://slack.com'],
          'font-src': ["'self'", "'https://a-slack-edge.com'"],
          'script-src': ["'self'"],
          'style-src': ["'self'"],
          'connect-src': ["'self'"],
        }),
      ]);

      webpackCompile(config, (csps) => {
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

    it('handles string values for policies where hashes and nonces are appended', (done) => {
      const config = createWebpackConfig([
        new HtmlWebpackPlugin({
          filename: path.join(WEBPACK_OUTPUT_DIR, 'index.html'),
          template: path.join(
            __dirname,
            'test-utils',
            'fixtures',
            'with-script-and-style.html'
          ),
        }),
        new CspHtmlWebpackPlugin({
          'script-src': "'self'",
          'style-src': "'self'",
        }),
      ]);

      webpackCompile(config, (csps) => {
        const expected =
          "base-uri 'self';" +
          " object-src 'none';" +
          " script-src 'self' 'sha256-ixjZMYNfWQWawUHioWOx2jBsTmfxucX7IlwsMt2jWvc=' 'nonce-mockedbase64string-1' 'nonce-mockedbase64string-2';" +
          " style-src 'self' 'sha256-MqG77yUiqBo4MMVZAl09WSafnQY4Uu3cSdZPKxaf9sQ=' 'nonce-mockedbase64string-3'";

        expect(csps['index.html']).toEqual(expected);
        done();
      });
    });

    it("doesn't add nonces for scripts / styles generated where their host has already been defined in the CSP, and 'strict-dynamic' doesn't exist in the policy", (done) => {
      const config = createWebpackConfig(
        [
          new HtmlWebpackPlugin({
            filename: path.join(WEBPACK_OUTPUT_DIR, 'index.html'),
            template: path.join(
              __dirname,
              'test-utils',
              'fixtures',
              'with-script-and-style.html'
            ),
          }),
          new CspHtmlWebpackPlugin({
            'script-src': ["'self'", 'https://my.cdn.com'],
            'style-src': ["'self'"],
          }),
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

    it("continues to add nonces to scripts / styles even if the host has already been whitelisted due to 'strict-dynamic' existing in the policy", (done) => {
      const config = createWebpackConfig(
        [
          new HtmlWebpackPlugin({
            filename: path.join(WEBPACK_OUTPUT_DIR, 'index.html'),
            template: path.join(
              __dirname,
              'test-utils',
              'fixtures',
              'with-script-and-style.html'
            ),
          }),
          new CspHtmlWebpackPlugin({
            'script-src': ["'self'", "'strict-dynamic'", 'https://my.cdn.com'],
            'style-src': ["'self'"],
          }),
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
      it('inserts a custom policy from a specific HtmlWebpackPlugin instance, if one is defined', (done) => {
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
                'connect-src': ["'self'"],
              },
            },
          }),
          new CspHtmlWebpackPlugin(),
        ]);

        webpackCompile(config, (csps) => {
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

      it('merges and overwrites policies, with a html webpack plugin instance policy taking precedence, followed by the csp instance, and then the default policy', (done) => {
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
                  "'https://b-slack-edge.com'",
                ],
              },
            },
          }),
          new CspHtmlWebpackPlugin({
            'base-uri': ["'self'", 'https://slack.com'],
            'font-src': ["'self'"],
          }),
        ]);

        webpackCompile(config, (csps) => {
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

      it('only adds a custom policy to the html file which has a policy defined; uses the default policy for any others', (done) => {
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
                'style-src': ["'https://b-slack-edge.com'"],
              },
            },
          }),
          new HtmlWebpackPlugin({
            filename: path.join(WEBPACK_OUTPUT_DIR, 'index-no-csp.html'),
            template: path.join(
              __dirname,
              'test-utils',
              'fixtures',
              'with-nothing.html'
            ),
          }),
          new CspHtmlWebpackPlugin(),
        ]);

        webpackCompile(config, (csps) => {
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
  });

  describe('Hash / Nonce enabled check', () => {
    it("doesn't add hashes to any policy rule if that policy rule has been globally disabled", (done) => {
      const config = createWebpackConfig([
        new HtmlWebpackPlugin({
          filename: path.join(WEBPACK_OUTPUT_DIR, 'index-1.html'),
          template: path.join(
            __dirname,
            'test-utils',
            'fixtures',
            'with-script-and-style.html'
          ),
        }),
        new HtmlWebpackPlugin({
          filename: path.join(WEBPACK_OUTPUT_DIR, 'index-2.html'),
          template: path.join(
            __dirname,
            'test-utils',
            'fixtures',
            'with-script-and-style.html'
          ),
        }),
        new CspHtmlWebpackPlugin(
          {},
          {
            hashEnabled: {
              'script-src': false,
              'style-src': false,
            },
          }
        ),
      ]);

      webpackCompile(config, (csps) => {
        const expected1 =
          "base-uri 'self';" +
          " object-src 'none';" +
          " script-src 'unsafe-inline' 'self' 'unsafe-eval' 'nonce-mockedbase64string-1' 'nonce-mockedbase64string-2';" +
          " style-src 'unsafe-inline' 'self' 'unsafe-eval' 'nonce-mockedbase64string-3'";

        const expected2 =
          "base-uri 'self';" +
          " object-src 'none';" +
          " script-src 'unsafe-inline' 'self' 'unsafe-eval' 'nonce-mockedbase64string-4' 'nonce-mockedbase64string-5';" +
          " style-src 'unsafe-inline' 'self' 'unsafe-eval' 'nonce-mockedbase64string-6'";

        // no hashes in either one of the script-src or style-src policies
        expect(csps['index-1.html']).toEqual(expected1);
        expect(csps['index-2.html']).toEqual(expected2);

        done();
      });
    });

    it("doesn't add nonces to any policy rule if that policy rule has been globally disabled", (done) => {
      const config = createWebpackConfig([
        new HtmlWebpackPlugin({
          filename: path.join(WEBPACK_OUTPUT_DIR, 'index-1.html'),
          template: path.join(
            __dirname,
            'test-utils',
            'fixtures',
            'with-script-and-style.html'
          ),
        }),
        new HtmlWebpackPlugin({
          filename: path.join(WEBPACK_OUTPUT_DIR, 'index-2.html'),
          template: path.join(
            __dirname,
            'test-utils',
            'fixtures',
            'with-script-and-style.html'
          ),
        }),
        new CspHtmlWebpackPlugin(
          {},
          {
            nonceEnabled: {
              'script-src': false,
              'style-src': false,
            },
          }
        ),
      ]);

      webpackCompile(config, (csps) => {
        const expected1 =
          "base-uri 'self';" +
          " object-src 'none';" +
          " script-src 'unsafe-inline' 'self' 'unsafe-eval' 'sha256-ixjZMYNfWQWawUHioWOx2jBsTmfxucX7IlwsMt2jWvc=';" +
          " style-src 'unsafe-inline' 'self' 'unsafe-eval' 'sha256-MqG77yUiqBo4MMVZAl09WSafnQY4Uu3cSdZPKxaf9sQ='";

        const expected2 =
          "base-uri 'self';" +
          " object-src 'none';" +
          " script-src 'unsafe-inline' 'self' 'unsafe-eval' 'sha256-ixjZMYNfWQWawUHioWOx2jBsTmfxucX7IlwsMt2jWvc=';" +
          " style-src 'unsafe-inline' 'self' 'unsafe-eval' 'sha256-MqG77yUiqBo4MMVZAl09WSafnQY4Uu3cSdZPKxaf9sQ='";

        // no nonces in either one of the script-src or style-src policies
        expect(csps['index-1.html']).toEqual(expected1);
        expect(csps['index-2.html']).toEqual(expected2);

        done();
      });
    });

    it("doesn't add hashes to a specific policy rule if that policy rule has been disabled for that instance of HtmlWebpackPlugin", (done) => {
      const config = createWebpackConfig([
        new HtmlWebpackPlugin({
          filename: path.join(WEBPACK_OUTPUT_DIR, 'index-no-hashes.html'),
          template: path.join(
            __dirname,
            'test-utils',
            'fixtures',
            'with-script-and-style.html'
          ),
          cspPlugin: {
            hashEnabled: {
              'script-src': false,
              'style-src': false,
            },
          },
        }),
        new HtmlWebpackPlugin({
          filename: path.join(WEBPACK_OUTPUT_DIR, 'index-hashes.html'),
          template: path.join(
            __dirname,
            'test-utils',
            'fixtures',
            'with-script-and-style.html'
          ),
        }),
        new CspHtmlWebpackPlugin(),
      ]);

      webpackCompile(config, (csps) => {
        const expectedNoHashes =
          "base-uri 'self';" +
          " object-src 'none';" +
          " script-src 'unsafe-inline' 'self' 'unsafe-eval' 'nonce-mockedbase64string-1' 'nonce-mockedbase64string-2';" +
          " style-src 'unsafe-inline' 'self' 'unsafe-eval' 'nonce-mockedbase64string-3'";

        const expectedHashes =
          "base-uri 'self';" +
          " object-src 'none';" +
          " script-src 'unsafe-inline' 'self' 'unsafe-eval' 'sha256-ixjZMYNfWQWawUHioWOx2jBsTmfxucX7IlwsMt2jWvc=' 'nonce-mockedbase64string-4' 'nonce-mockedbase64string-5';" +
          " style-src 'unsafe-inline' 'self' 'unsafe-eval' 'sha256-MqG77yUiqBo4MMVZAl09WSafnQY4Uu3cSdZPKxaf9sQ=' 'nonce-mockedbase64string-6'";

        // no hashes in index-no-hashes script-src or style-src policies
        expect(csps['index-no-hashes.html']).toEqual(expectedNoHashes);
        expect(csps['index-hashes.html']).toEqual(expectedHashes);

        done();
      });
    });

    it("doesn't add nonces to a specific policy rule if that policy rule has been disabled for that instance of HtmlWebpackPlugin", (done) => {
      const config = createWebpackConfig([
        new HtmlWebpackPlugin({
          filename: path.join(WEBPACK_OUTPUT_DIR, 'index-no-nonce.html'),
          template: path.join(
            __dirname,
            'test-utils',
            'fixtures',
            'with-script-and-style.html'
          ),
          cspPlugin: {
            nonceEnabled: {
              'script-src': false,
              'style-src': false,
            },
          },
        }),
        new HtmlWebpackPlugin({
          filename: path.join(WEBPACK_OUTPUT_DIR, 'index-nonce.html'),
          template: path.join(
            __dirname,
            'test-utils',
            'fixtures',
            'with-script-and-style.html'
          ),
        }),
        new CspHtmlWebpackPlugin(),
      ]);

      webpackCompile(config, (csps) => {
        const expectedNoNonce =
          "base-uri 'self';" +
          " object-src 'none';" +
          " script-src 'unsafe-inline' 'self' 'unsafe-eval' 'sha256-ixjZMYNfWQWawUHioWOx2jBsTmfxucX7IlwsMt2jWvc=';" +
          " style-src 'unsafe-inline' 'self' 'unsafe-eval' 'sha256-MqG77yUiqBo4MMVZAl09WSafnQY4Uu3cSdZPKxaf9sQ='";

        const expectedNonce =
          "base-uri 'self';" +
          " object-src 'none';" +
          " script-src 'unsafe-inline' 'self' 'unsafe-eval' 'sha256-ixjZMYNfWQWawUHioWOx2jBsTmfxucX7IlwsMt2jWvc=' 'nonce-mockedbase64string-1' 'nonce-mockedbase64string-2';" +
          " style-src 'unsafe-inline' 'self' 'unsafe-eval' 'sha256-MqG77yUiqBo4MMVZAl09WSafnQY4Uu3cSdZPKxaf9sQ=' 'nonce-mockedbase64string-3'";

        // no nonce in index-no-nonce script-src or style-src policies
        expect(csps['index-no-nonce.html']).toEqual(expectedNoNonce);
        expect(csps['index-nonce.html']).toEqual(expectedNonce);

        done();
      });
    });
  });

  describe('Plugin enabled check', () => {
    it("doesn't modify the html if enabled is the bool false", (done) => {
      const config = createWebpackConfig([
        new HtmlWebpackPlugin({
          filename: path.join(WEBPACK_OUTPUT_DIR, 'index.html'),
          template: path.join(
            __dirname,
            'test-utils',
            'fixtures',
            'with-no-meta-tag.html'
          ),
        }),
        new CspHtmlWebpackPlugin(
          {},
          {
            enabled: false,
          }
        ),
      ]);

      webpackCompile(config, (csps, selectors) => {
        expect(csps['index.html']).toBeUndefined();
        expect(selectors['index.html']('meta').length).toEqual(1);
        done();
      });
    });

    it("doesn't modify the html if the `cspPlugin.enabled` option in HtmlWebpack Plugin is false", (done) => {
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
            enabled: false,
          },
        }),
        new CspHtmlWebpackPlugin(),
      ]);

      webpackCompile(config, (csps, selectors) => {
        expect(csps['index.html']).toBeUndefined();
        expect(selectors['index.html']('meta').length).toEqual(1);
        done();
      });
    });

    it("doesn't modify the html if enabled is a function which return false", (done) => {
      const config = createWebpackConfig([
        new HtmlWebpackPlugin({
          filename: path.join(WEBPACK_OUTPUT_DIR, 'index.html'),
          template: path.join(
            __dirname,
            'test-utils',
            'fixtures',
            'with-no-meta-tag.html'
          ),
        }),
        new CspHtmlWebpackPlugin(
          {},
          {
            enabled: () => false,
          }
        ),
      ]);

      webpackCompile(config, (csps, selectors) => {
        expect(csps['index.html']).toBeUndefined();
        expect(selectors['index.html']('meta').length).toEqual(1);
        done();
      });
    });

    it("doesn't modify html from the HtmlWebpackPlugin instance which has been disabled", (done) => {
      const config = createWebpackConfig([
        new HtmlWebpackPlugin({
          filename: path.join(WEBPACK_OUTPUT_DIR, 'index-enabled.html'),
          template: path.join(
            __dirname,
            'test-utils',
            'fixtures',
            'with-no-meta-tag.html'
          ),
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
            enabled: false,
          },
        }),
        new CspHtmlWebpackPlugin(),
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
    it('still adds the CSP policy into the CSP meta tag even if the content attribute is missing', (done) => {
      const config = createWebpackConfig([
        new HtmlWebpackPlugin({
          filename: path.join(WEBPACK_OUTPUT_DIR, 'index.html'),
          template: path.join(
            __dirname,
            'test-utils',
            'fixtures',
            'with-no-content-attr.html'
          ),
        }),
        new CspHtmlWebpackPlugin(),
      ]);

      webpackCompile(config, (csps) => {
        const expected =
          "base-uri 'self';" +
          " object-src 'none';" +
          " script-src 'unsafe-inline' 'self' 'unsafe-eval' 'nonce-mockedbase64string-1';" +
          " style-src 'unsafe-inline' 'self' 'unsafe-eval'";

        expect(csps['index.html']).toEqual(expected);
        done();
      });
    });

    it('adds meta tag with completed policy when no meta tag is specified', (done) => {
      const config = createWebpackConfig([
        new HtmlWebpackPlugin({
          filename: path.join(WEBPACK_OUTPUT_DIR, 'index.html'),
          template: path.join(
            __dirname,
            'test-utils',
            'fixtures',
            'with-no-meta-tag.html'
          ),
        }),
        new CspHtmlWebpackPlugin(),
      ]);

      webpackCompile(config, (csps) => {
        const expected =
          "base-uri 'self';" +
          " object-src 'none';" +
          " script-src 'unsafe-inline' 'self' 'unsafe-eval' 'nonce-mockedbase64string-1';" +
          " style-src 'unsafe-inline' 'self' 'unsafe-eval'";

        expect(csps['index.html']).toEqual(expected);
        done();
      });
    });

    it('adds meta tag with completed policy when no template is specified', (done) => {
      const config = createWebpackConfig([
        new HtmlWebpackPlugin({
          filename: path.join(WEBPACK_OUTPUT_DIR, 'index.html'),
        }),
        new CspHtmlWebpackPlugin(),
      ]);

      webpackCompile(config, (csps) => {
        const expected =
          "base-uri 'self';" +
          " object-src 'none';" +
          " script-src 'unsafe-inline' 'self' 'unsafe-eval' 'nonce-mockedbase64string-1';" +
          " style-src 'unsafe-inline' 'self' 'unsafe-eval'";

        expect(csps['index.html']).toEqual(expected);
        done();
      });
    });

    it("adds the meta tag as the top most meta tag to ensure that the CSP is defined before we try loading any other scripts, if it doesn't exist", (done) => {
      const config = createWebpackConfig([
        new HtmlWebpackPlugin({
          filename: path.join(WEBPACK_OUTPUT_DIR, 'index.html'),
          template: path.join(
            __dirname,
            'test-utils',
            'fixtures',
            'with-script-and-style.html'
          ),
        }),
        new CspHtmlWebpackPlugin(),
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

  describe('Custom process function', () => {
    it('Allows the process function to be overwritten', (done) => {
      const processFn = jest.fn();
      const builtPolicy = `base-uri 'self'; object-src 'none'; script-src 'unsafe-inline' 'self' 'unsafe-eval' 'sha256-ixjZMYNfWQWawUHioWOx2jBsTmfxucX7IlwsMt2jWvc=' 'nonce-mockedbase64string-1' 'nonce-mockedbase64string-2'; style-src 'unsafe-inline' 'self' 'unsafe-eval' 'sha256-MqG77yUiqBo4MMVZAl09WSafnQY4Uu3cSdZPKxaf9sQ=' 'nonce-mockedbase64string-3'`;

      const config = createWebpackConfig([
        new HtmlWebpackPlugin({
          filename: path.join(WEBPACK_OUTPUT_DIR, 'index.html'),
          template: path.join(
            __dirname,
            'test-utils',
            'fixtures',
            'with-script-and-style.html'
          ),
        }),
        new CspHtmlWebpackPlugin(
          {},
          {
            processFn,
          }
        ),
      ]);

      webpackCompile(config, (csps) => {
        // we've overwritten the default processFn, which writes the policy into the html file
        // so it won't exist in this object anymore.
        expect(csps['index.html']).toBeUndefined();

        // The processFn should receive the built policy as it's first arg
        expect(processFn).toHaveBeenCalledWith(
          builtPolicy,
          expect.anything(),
          expect.anything(),
          expect.anything()
        );

        done();
      });
    });

    it('only overwrites the processFn for the HtmlWebpackInstance where it has been defined', (done) => {
      const processFn = jest.fn();
      const index1BuiltPolicy = `base-uri 'self'; object-src 'none'; script-src 'unsafe-inline' 'self' 'unsafe-eval' 'sha256-ixjZMYNfWQWawUHioWOx2jBsTmfxucX7IlwsMt2jWvc=' 'nonce-mockedbase64string-1' 'nonce-mockedbase64string-2'; style-src 'unsafe-inline' 'self' 'unsafe-eval' 'sha256-MqG77yUiqBo4MMVZAl09WSafnQY4Uu3cSdZPKxaf9sQ=' 'nonce-mockedbase64string-3'`;
      const index2BuiltPolicy = `base-uri 'self'; object-src 'none'; script-src 'unsafe-inline' 'self' 'unsafe-eval' 'sha256-ixjZMYNfWQWawUHioWOx2jBsTmfxucX7IlwsMt2jWvc=' 'nonce-mockedbase64string-4' 'nonce-mockedbase64string-5'; style-src 'unsafe-inline' 'self' 'unsafe-eval' 'sha256-MqG77yUiqBo4MMVZAl09WSafnQY4Uu3cSdZPKxaf9sQ=' 'nonce-mockedbase64string-6'`;

      const config = createWebpackConfig([
        new HtmlWebpackPlugin({
          filename: path.join(WEBPACK_OUTPUT_DIR, 'index-1.html'),
          template: path.join(
            __dirname,
            'test-utils',
            'fixtures',
            'with-script-and-style.html'
          ),
          cspPlugin: {
            processFn,
          },
        }),
        new HtmlWebpackPlugin({
          filename: path.join(WEBPACK_OUTPUT_DIR, 'index-2.html'),
          template: path.join(
            __dirname,
            'test-utils',
            'fixtures',
            'with-script-and-style.html'
          ),
        }),
        new CspHtmlWebpackPlugin(),
      ]);

      webpackCompile(config, (csps) => {
        // it won't exist in the html file since we overwrote processFn
        expect(csps['index-1.html']).toBeUndefined();
        // processFn wasn't overwritten here, so this should be added to the html file as normal
        expect(csps['index-2.html']).toEqual(index2BuiltPolicy);

        // index-1.html should have used our custom function defined
        expect(processFn).toHaveBeenCalledWith(
          index1BuiltPolicy,
          expect.anything(),
          expect.anything(),
          expect.anything()
        );

        done();
      });
    });

    it('Allows to generate a file containing the policy', (done) => {
      function generateCSPFile(
        builtPolicy,
        _htmlPluginData,
        _obj,
        compilation
      ) {
        compilation.emitAsset('csp.conf', new RawSource(builtPolicy));
      }
      const index1BuiltPolicy = `base-uri 'self'; object-src 'none'; script-src 'unsafe-inline' 'self' 'unsafe-eval' 'sha256-ixjZMYNfWQWawUHioWOx2jBsTmfxucX7IlwsMt2jWvc=' 'nonce-mockedbase64string-1' 'nonce-mockedbase64string-2'; style-src 'unsafe-inline' 'self' 'unsafe-eval' 'sha256-MqG77yUiqBo4MMVZAl09WSafnQY4Uu3cSdZPKxaf9sQ=' 'nonce-mockedbase64string-3'`;

      const config = createWebpackConfig([
        new HtmlWebpackPlugin({
          filename: path.join(WEBPACK_OUTPUT_DIR, 'index-1.html'),
          template: path.join(
            __dirname,
            'test-utils',
            'fixtures',
            'with-script-and-style.html'
          ),
        }),
        new CspHtmlWebpackPlugin(
          {},
          {
            processFn: generateCSPFile,
          }
        ),
      ]);

      webpackCompile(config, (csps, selectors, fileSystem) => {
        const cspFileContent = fileSystem
          .readFileSync(path.join(WEBPACK_OUTPUT_DIR, 'csp.conf'), 'utf8')
          .toString();

        // it won't exist in the html file since we overwrote processFn
        expect(csps['index-1.html']).toBeUndefined();

        // A file has been generated
        expect(cspFileContent).toEqual(index1BuiltPolicy);

        done();
      });
    });
  });

  describe('HTML parsing', () => {
    it("doesn't encode escaped HTML entities", (done) => {
      const config = createWebpackConfig([
        new HtmlWebpackPlugin({
          filename: path.join(WEBPACK_OUTPUT_DIR, 'index.html'),
          template: path.join(
            __dirname,
            'test-utils',
            'fixtures',
            'with-escaped-html.html'
          ),
        }),
        new CspHtmlWebpackPlugin(),
      ]);

      webpackCompile(config, (_, selectors) => {
        const $ = selectors['index.html'];
        expect($('body').html().trim()).toEqual(
          '&lt;h1&gt;Escaped Content&lt;h1&gt;'
        );
        done();
      });
    });

    it('generates a hash for style tags wrapped in noscript tags', (done) => {
      const config = createWebpackConfig([
        new HtmlWebpackPlugin({
          filename: path.join(WEBPACK_OUTPUT_DIR, 'index.html'),
          template: path.join(
            __dirname,
            'test-utils',
            'fixtures',
            'with-noscript-tags.html'
          ),
        }),
        new CspHtmlWebpackPlugin(),
      ]);

      webpackCompile(config, (csps) => {
        const expected =
          "base-uri 'self';" +
          " object-src 'none';" +
          " script-src 'unsafe-inline' 'self' 'unsafe-eval' 'nonce-mockedbase64string-1';" +
          " style-src 'unsafe-inline' 'self' 'unsafe-eval' 'sha256-JUH8Xh1Os2tA1KU3Lfxn5uZXj2Q/a/i0UVMzpWO4uOU='";

        expect(csps['index.html']).toEqual(expected);

        done();
      });
    });

    it('honors xhtml mode if set on the html-webpack-plugin instance', (done) => {
      const config = createWebpackConfig([
        new HtmlWebpackPlugin({
          filename: path.join(WEBPACK_OUTPUT_DIR, 'index.html'),
          template: path.join(
            __dirname,
            'test-utils',
            'fixtures',
            'with-xhtml.html'
          ),
          xhtml: true,
        }),
        new CspHtmlWebpackPlugin(),
      ]);

      webpackCompile(config, (csps, selectors, fileSystem) => {
        const xhtmlContents = fileSystem
          .readFileSync(path.join(WEBPACK_OUTPUT_DIR, 'index.html'), 'utf8')
          .toString();

        // correct doctype
        expect(xhtmlContents).toContain(
          '<!DOCTYPE composition PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">'
        );

        // self closing tag
        expect(xhtmlContents).toContain(
          '<meta name="author" content="Slack"/>'
        );

        // csp has been added in
        expect(xhtmlContents).toContain(
          `<meta http-equiv="Content-Security-Policy" content="base-uri 'self'; object-src 'none'; script-src 'unsafe-inline' 'self' 'unsafe-eval' 'nonce-mockedbase64string-1'; style-src 'unsafe-inline' 'self' 'unsafe-eval'"/>`
        );

        done();
      });
    });
  });
});
