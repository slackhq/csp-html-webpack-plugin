module.exports = {
  "extends": [
    "airbnb-base",
    "prettier"
  ],
  "plugins": [
    "prettier"
  ],
  "env": {
    "es6": true,
    "node": true
  },
  "rules": {
    "prettier/prettier": ["error", { "singleQuote": true }]
  },
  "globals": {
    "document": true,
    "afterAll": true,
    "afterEach": true,
    "beforeAll": true,
    "beforeEach": true,
    "describe": true,
    "expect": true,
    "it": true
  }
};
