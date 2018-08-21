const crypto = require('crypto')
const { DateTime } = require('luxon')
const { parse: parseUrl } = require('url')

module.exports.requestHooks = [
  async context => {
    const { store, request } = context
    const keyId = await store.getItem('keyId')
    let privateKey = await store.getItem('privateKey')
    privateKey = `-----BEGIN PRIVATE KEY-----\n${privateKey}\n-----END PRIVATE KEY-----`

    const parsedUrl = parseUrl(request.getUrl())

    const algorithmBits = 256
    const hashAlgorithm = `sha${algorithmBits}`
    const digestAlgorithm = `SHA-${algorithmBits}`
    const signAlgorithm = `RSA-SHA${algorithmBits}`

    const date = DateTime.utc().toRFC2822()

    const digestHash = crypto.createHash(hashAlgorithm)
    const digest = digestHash.update(request.getBodyText()).digest('base64')

    const signatureString = []
    signatureString.push(`(request-target): ${request.getMethod().toLowerCase()} ${parsedUrl.path}`)
    signatureString.push(`host: ${parsedUrl.hostname}`)
    signatureString.push(`digest: ${digestAlgorithm}=${digest}`)
    signatureString.push(`date: ${date}`)
    if (request.hasHeader('Content-Type')) signatureString.push(`content-type: ${request.getHeader('Content-Type')}`)
    const signature = signatureString.join('\n')

    const signatureSign = crypto.createSign(signAlgorithm)
    const signedSignature = signatureSign.update(signature).sign(privateKey, 'base64')

    const authorization = `Signature keyId="${keyId}", algorithm="${signAlgorithm.toLowerCase()}", headers="(request-target) host digest date${request.hasHeader('Content-Type') ? ' content-type' : ''}", signature="${signedSignature}"`

    request.setHeader('Digest', `${digestAlgorithm}=${digest}`)
    request.setHeader('Date', date)
    request.setHeader('Authorization', authorization)
  }
]

module.exports.templateTags = [{
  name: 'httpsignature',
  displayName: 'HTTP Signature',
  description: 'sign http requests',

  args: [
    {
      displayName: 'Key ID',
      type: 'string'
    },
    {
      displayName: 'Private Key',
      type: 'string'
    }
  ],

  async run (context, keyId, privateKey) {
    await context.store.setItem('keyId', keyId)
    await context.store.setItem('privateKey', privateKey)
    return ' '
  }
}]
