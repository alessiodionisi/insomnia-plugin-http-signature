const crypto = require('crypto')
const { parse: parseUrl } = require('url')

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

  async run(context, keyId, privateKey) {
    console.log(context)
    const request = await context.util.models.request.getById(context.meta.requestId)
    const requestUrl = await context.util.render(request.url)

    if (!keyId) throw new Error('missing keyId')
    if (!privateKey) throw new Error('missing privateKey')

    const parsedUrl = parseUrl(requestUrl)

    const algorithmBits = 256
    const signAlgorithm = `RSA-SHA${algorithmBits}`

    const signatureString = []
    signatureString.push(`(request-target): ${request.method.toLowerCase()} ${parsedUrl.path}`)
    signatureString.push(`host: ${parsedUrl.hostname}`)
    const signature = signatureString.join('\n')

    const signatureSign = crypto.createSign(signAlgorithm)
    const signedSignature = signatureSign.update(signature).sign(`-----BEGIN RSA PRIVATE KEY-----\n${privateKey}\n-----END RSA PRIVATE KEY-----`, 'base64')

    const authorization = `keyId="${keyId}", algorithm="${signAlgorithm.toLowerCase()}", headers="(request-target) host", signature="${signedSignature}"`
    return authorization
  }
}]
