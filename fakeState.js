const crypto = require('crypto');

const randomString = (length) => {
  return crypto.randomBytes(length).toString('hex').slice(0, length);
};

const sleep = async (ms) => {
  return new Promise(res => setTimeout(res, ms));
};

const fakeState = () => {
  return [
    {
      key: 'datr',
      value: randomString(24),
      domain: 'facebook.com',
      path: '/',
      hostOnly: true,
      creation: new Date().toISOString(),
      lastAccessed: new Date().toISOString()
    },
    {
      key: 'ps_l',
      value: Math.floor(Math.random() * 2).toString(),
      domain: 'facebook.com',
      path: '/',
      hostOnly: true,
      creation: new Date().toISOString(),
      lastAccessed: new Date().toISOString(),
    },
    {
      key: 'ps_n',
      value: Math.floor(Math.random() * 2).toString(),
      domain: 'facebook.com',
      path: '/',
      hostOnly: true,
      creation: new Date().toISOString(),
      lastAccessed: new Date().toISOString()
    },
    {
      key: 'sb',
      value: randomString(24),
      domain: 'facebook.com',
      path: '/',
      hostOnly: true,
      creation: new Date().toISOString(),
      lastAccessed: new Date().toISOString()
    },
    {
      key: 'c_user',
      value: randomString(14),
      domain: 'facebook.com',
      path: '/',
      hostOnly: true,
      creation: new Date().toISOString(),
      lastAccessed: new Date().toISOString()
    },
    {
      key: 'fr',
      value: `${randomString(8)}.${randomString(18)}.${randomString(8)}..AAA.0.0.${randomString(8)}.${randomString(12)}`,
      domain: 'facebook.com',
      path: '/',
      hostOnly: true,
      creation: new Date().toISOString(),
      lastAccessed: new Date().toISOString()
    },
    {
      key: 'xs',
      value: `42%3A${randomString(10)}%3A2%3A${Math.floor(Date.now() / 1000)}%3A-1%3A7861`,
      domain: 'facebook.com',
      path: '/',
      hostOnly: true,
      creation: new Date().toISOString(),
      lastAccessed: new Date().toISOString()
    },
    {
      key: 'm_page_voice',
      value: randomString(14),
      domain: 'facebook.com',
      path: '/',
      hostOnly: true,
      creation: new Date().toISOString(),
      lastAccessed: new Date().toISOString()
    },
  ];
};

module.exports = {
  randomString,
  fakeState,
  sleep
};
