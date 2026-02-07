const sleep = time => new Promise(resolve => setTimeout(resolve, time))

const challenges = new Map([
  ['my-name', {
    name: 'My Name ___',
    timeout: 2000,
    handler: async (url, ctx) => {
      const page = await ctx.newPage()
      await page.setCookie({ name: 'flag', value: 'grey{fake_flag_for_testing}', url: "http://challenge:8080/" })
      await page.goto(url, { timeout: 1000, waitUntil: 'domcontentloaded' })
      await sleep(500)
    }
  }]
])

module.exports = {
  challenges
}