import { Certificate, IKsuCertificate, IKsuUser } from './cert'
import * as jwt from 'jsonwebtoken'
import * as router from 'koa-router'
import * as Koa from 'koa'
import * as _ from 'lodash'

export class Auth {
  private certificate: Certificate
  constructor(certificatePath: string) {
    this.certificate = Certificate.fromFile(certificatePath)
  }
  async  auth(ctx: Koa.ParameterizedContext<{}, router.IRouterContext>, next: () => Promise<any>) {
    const berear: string = ctx.get('Authorization')
    const token = berear.split(' ')[1]
    if (!token) ctx.throw(500, 'Authorization failed')
    let authData: IKsuCertificate | IKsuUser = null
    try {
      const data = jwt.verify(token, this.certificate.getPublicString())
      if (_.get(data, 'username')) {
        authData = <IKsuUser>data
      } else {
        authData = <IKsuCertificate>data
      }
    } catch {
      ctx.throw(500, 'Broken authorization token')
    }
    _.set(ctx, 'user', { type: typeof authData, data: authData })
    _.set(ctx, 'ca', this.certificate)
    await next()
  }
}