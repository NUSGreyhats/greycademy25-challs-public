const puppeteer = require('puppeteer')
const net = require('net')

const BASE_URL = process.env.BASE_URL || 'http://challenge:31001/'
const FLAG = process.env.FLAG || 'grey{h3y_whO_sT0l3_mY_c00k13S!!!}'

const browserPool = []

const getBrowser = async () => {
    if (browserPool.length > 0) {
        return browserPool.pop()
    }
    return await puppeteer.launch({
        headless: true,
        args: ['--js-flags=--jitless', '--no-sandbox', '--disable-setuid-sandbox']
    })
}

const returnBrowser = (browser) => {
    browserPool.push(browser)
}

const visitUrl = async (url) => {
    const browser = await getBrowser()
    const page = await browser.newPage()
    const hostname = new URL(BASE_URL).hostname
    await page.setCookie({
        name: 'admin_flag',
        value: FLAG,
        domain: hostname,
        path: '/',
        httpOnly: false,
        secure: false
    })
    try {
        await page.goto(BASE_URL + url, { waitUntil: 'networkidle2', timeout: 5000 })
    }
    catch (e) {
        console.log(e)
    }
    await page.close()
    returnBrowser(browser)
}

setInterval(() => {
    while (browserPool.length > 0) {
        const browser = browserPool.pop()
        browser.close()
    }
}, 5 * 60 * 1000)

const server = net.createServer((socket) => {
    socket.on('data', async (data) => {
        const url = data.toString().trim()
        await visitUrl(url)
    })
})

server.listen(3001, () => {
    console.log('Listening on port 3001')
})