const HtmlWebpackPlugin = require('html-webpack-plugin');
const {
  createWebpackConfig,
  webpackCompile
} = require('./test-utils/webpack-helpers');

describe('CspHtmlWebpackPlugin', () => {
  it('works', done => {
    const config = createWebpackConfig([new HtmlWebpackPlugin()]);
    webpackCompile(config, () => {
      done();
    });
  });
});
