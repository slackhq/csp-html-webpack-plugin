require('./common');

require.ensure([], () => {
  require('./async'); // eslint-disable-line global-require
});

document.body.innerHTML += '<p>index.js</p>';
