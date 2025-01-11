const browsers = [{
    name: 'Mozilla/5.0',
    engines: [{
        engine: 'AppleWebKit/537.36 (KHTML, like Gecko)',
        browsers: ['Chrome',
            'Safari',
            'Edge']
    },
        {
            engine: 'Gecko/20100101',
            browsers: ['Firefox']
        },
    ]
}];

const mobileDevices = [{
    device: 'iPhone 12',
    os: 'iPhone; CPU iPhone OS',
    versions: ['14_4',
        '15_0',
        '16_0',
        '13_3'],
    browsers: ['Safari',
        'Chrome']
},
    {
        device: 'iPhone 13',
        os: 'iPhone; CPU iPhone OS',
        versions: ['14_4',
            '15_0',
            '16_0'],
        browsers: ['Safari',
            'Chrome']
    },
    {
        device: 'Samsung Galaxy S20',
        os: 'Linux; Android',
        versions: ['10',
            '11',
            '12',
            '13'],
        browsers: ['Chrome',
            'Firefox']
    },
    {
        device: 'Samsung Galaxy S21',
        os: 'Linux; Android',
        versions: ['10',
            '11',
            '12'],
        browsers: ['Chrome',
            'Firefox']
    },
    {
        device: 'Google Pixel 5',
        os: 'Linux; Android',
        versions: ['10',
            '11',
            '12'],
        browsers: ['Chrome',
            'Firefox']
    },
    {
        device: 'Google Pixel 6',
        os: 'Linux; Android',
        versions: ['11',
            '12'],
        browsers: ['Chrome',
            'Firefox']
    },
    {
        device: 'iPhone SE',
        os: 'iPhone; CPU iPhone OS',
        versions: ['13_3',
            '14_4',
            '15_0'],
        browsers: ['Safari',
            'Chrome']
    },
    {
        device: 'iPad Pro',
        os: 'iPad; CPU OS',
        versions: ['14_4',
            '15_0',
            '16_0'],
        browsers: ['Safari',
            'Chrome']
    },
    {
        device: 'Infinix Note 10',
        os: 'Linux; Android',
        versions: ['10',
            '11'],
        browsers: ['Chrome',
            'Firefox']
    },
    {
        device: 'Infinix Zero 8',
        os: 'Linux; Android',
        versions: ['10',
            '11'],
        browsers: ['Chrome',
            'Firefox']
    },
    {
        device: 'Xiaomi Mi 11',
        os: 'Linux; Android',
        versions: ['10',
            '11',
            '12'],
        browsers: ['Chrome',
            'Firefox']
    },
    {
        device: 'Xiaomi Redmi Note 10',
        os: 'Linux; Android',
        versions: ['10',
            '11',
            '12'],
        browsers: ['Chrome',
            'Edge']
    },
    {
        device: 'Tecno Camon 16',
        os: 'Linux; Android',
        versions: ['10',
            '11'],
        browsers: ['Chrome',
            'Firefox']
    },
    {
        device: 'Tecno Spark 6',
        os: 'Linux; Android',
        versions: ['10',
            '11'],
        browsers: ['Chrome',
            'Firefox']
    },
    {
        device: 'Redmagic 6',
        os: 'Linux; Android',
        versions: ['11',
            '12'],
        browsers: ['Chrome',
            'Firefox']
    },
    {
        device: 'Redmagic 5G',
        os: 'Linux; Android',
        versions: ['10',
            '11'],
        browsers: ['Chrome',
            'Firefox']
    },
    {
        device: 'Redmagic 7',
        os: 'Linux; Android',
        versions: ['11',
            '12'],
        browsers: ['Chrome',
            'Firefox']
    }];

const desktopPlatforms = [{
    platform: 'Windows NT 10.0',
    browsers: ['Chrome',
        'Edge',
        'Firefox']
},
    {
        platform: 'Macintosh; Intel Mac OS X 10_15_7',
        browsers: ['Safari',
            'Chrome',
            'Firefox']
    },
    {
        platform: 'X11; Linux x86_64',
        browsers: ['Firefox',
            'Chrome']
    }];

function getRandomElement(arr) {
    return arr[Math.floor(Math.random() * arr.length)];
}

function generateUserAgent() {
    const isMobile = Math.random() < 0.8; // 70% chance for mobile devices
    let os;
    let browserDetails;
    let deviceName = '';

    if (isMobile) {
        const selectedDevice = getRandomElement(mobileDevices);
        const version = getRandomElement(selectedDevice.versions);
        os = `${selectedDevice.os} ${version} like Mac OS X`;
        deviceName = `; ${selectedDevice.device}`;
        const browser = getRandomElement(selectedDevice.browsers);
        browserDetails = {
            name: browser,
            engine: 'AppleWebKit/537.36 (KHTML, like Gecko)'
        };
    } else {
        const selectedPlatform = getRandomElement(desktopPlatforms);
        os = selectedPlatform.platform;
        const browser = getRandomElement(selectedPlatform.browsers);
        const engine = browser === 'Firefox' ? 'Gecko/20100101': 'AppleWebKit/537.36 (KHTML, like Gecko)';
        browserDetails = {
            name: browser,
            engine: engine
        };
    }

    const browserVersion = browserDetails.name === 'Chrome' ? '117.0.5938.92': browserDetails.name === 'Safari' ? '605.1.15': '91.0.4472.124';
    const safariVersion = browserDetails.name === 'Safari' ? '605.1': '537.36';

    return `${browsers[0].name} (${os}${deviceName}) ${browserDetails.engine} ${browserDetails.name}/${browserVersion} Safari/${safariVersion}`;
}

module.exports = {
    generateUserAgent
}