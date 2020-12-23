module.exports = {
  extends: ['airbnb-base', 'prettier'],
  plugins: ['prettier'],
  env: {
    es6: true,
    node: true,
  },
  rules: {
    'prettier/prettier': ['error', { singleQuote: true }],
    'import/no-extraneous-dependencies': [
      'error',
      { devDependencies: ['test-utils/**/*', '**/*.jest.js'] },
    ],
  },
  globals: {
    document: true,
  },
  overrides: [
    {
      files: ['*.spec.js', '*.jest.js', 'webpack-helpers.js'],
      globals: {
        jest: true,
        afterAll: true,
        afterEach: true,
        beforeAll: true,
        beforeEach: true,
        describe: true,
        expect: true,
        it: true,
      },
    },
  ],
};
