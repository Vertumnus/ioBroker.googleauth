/*eslint semi: ["error", "never", { "beforeStatementContinuationChars": "never"}] */
/*eslint quotes: ["error", "single"]*/
/*eslint-env es6*/

const path = require('path')
const express = require('express')
const passport = require('passport')
const GoogleStrategy = require('passport-google-oauth20').Strategy

const ONE_MONTH_SEC = 30 * 24 * 3600

/**
 * Extension for Web Server
 * Register Google Authentication at passport
 * Provide routes for Google Authentication
 *
 * @class
 * @param {object} server http or https node.js object
 * @param {object} webSettings settings of the web server, like <pre><code>{secure: settings.secure, port: settings.port}</code></pre>
 * @param {object} adapter web adapter object
 * @param {object} instanceSettings instance object with common and native
 * @param {object} app express application
 */
class WebExtension {
   constructor(server, webSettings, adapter, instanceSettings, app) {
      this.config = instanceSettings.native

      passport.use(new GoogleStrategy({
         clientID: this.config.clientId,
         clientSecret: this.config.clientSecret,
         userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo',
         callbackURL: '/login/google/cb',
         passReqToCallback: true,
         proxy: this.config.proxy
      }, (req, accessToken, refreshToken, profile, done) => {
         // get all users
         adapter.log.debug(instanceSettings.common.name + ': Check users for Google ID')
         adapter.getForeignObjects('system.user.*', 'user', (err, oUsers) => {
            if(err){
               adapter.log.info(instanceSettings.common.name + ': ' + err)
               return done(err)
            }

            // try to find the user with the given google user id
            // and for the initial case by local login take the user id (for object access)
            let sUserObjectId
            for(let [sUserId, oUser] of Object.entries(oUsers)){
               // transform original user name into an id like user name (which is also applied by local login on req.user)
               let sUserName = oUser.common.name.toString().replace(this.FORBIDDEN_CHARS, '_').replace(/\s/g, '_').replace(/\./g, '_').toLowerCase();

               if(oUser.native && oUser.native.googleId === profile.id){
                  adapter.log.debug(instanceSettings.common.name + ': User found -> ' + sUserName)
                  return done(null, sUserName)
               }
               if(req.isAuthenticated() && (sUserName === req.user || sUserId === `system.user.${req.user}`)){
                  sUserObjectId = sUserId
               }
            }

            // no local logged in user? -> error
            if(!req.isAuthenticated()){ 
               adapter.log.debug(instanceSettings.common.name + ': No user logged in!')
               return done(null, false, { error: 'Login2Register' })
            }

            // No user found, so take the local logged in user and assign google id
            adapter.log.debug(instanceSettings.common.name + ': User=' + sUserObjectId + ', Loginname=' + req.user)

            adapter.extendForeignObject(sUserObjectId, {
               native: {
                  googleId: profile.id
               }
            }, (err, oObject) => {
               if(err){
                  return done(err)
               }
               adapter.log.info(instanceSettings.common.name + ': User ' + req.user + ' associated to Google with ID ' + oObject.value.native.googleId)
               done(null, req.user)
            })
         })
      }))
      
      // provide image for sign in
      app.use('/login/google/img', express.static(path.join(__dirname, 'www/img')))
      
      app.post('/login/google', (req, res, next) => {
         adapter.log.debug(instanceSettings.common.name + ': [auth] Session ID = ' + req.session.id)
         if(this.isTrue(req.body.firsttime)){
            passport.authenticate('local', (err, user) => {
               if(err){
                  return adapter.log.warn(instanceSettings.common.name + ': User login failed - ' + err)
               }
               adapter.log.debug(instanceSettings.common.name + ': User logged in local -> ' + JSON.stringify(user))
               req.login(user.user, err => {
                  if(err) 
                     return next(err)
                  next()
               })
            })(req, res, next)
         }
         else{
            next()
         }
      })
      app.post('/login/google', (req, res, next) => {
         passport.authenticate('google', {
            scope: ['profile'],
            state: JSON.stringify({ 
               href: req.query.href, // take value of parameter href from second submatch
               stay: this.isTrue(req.body.stayloggedin)
            })
         })(req, res, next)
      })
      
      app.get('/login/google/cb', passport.authenticate('google', {
         failureRedirect: '/login',
         keepSessionInfo: true
      }), (req, res) => {
         let oState = JSON.parse(req.query.state)
         let sTarget = '/'
         if(oState){
            sTarget = oState.href || sTarget
            req.session.cookie.maxAge = webSettings.ttl * 1000
            if(oState.stay && ONE_MONTH_SEC > webSettings.ttl){
               req.session.cookie.maxAge = ONE_MONTH_SEC * 1000
            }
         }
         adapter.log.debug(instanceSettings.common.name + ': [cb] Session ID = ' + req.session.id)
         adapter.log.debug(instanceSettings.common.name + ': User ' + req.user + ' logged in (' + req.isAuthenticated() + ') via Google; redirect to ' + sTarget)
         req.session.save(err => {
            if(err)
               adapter.log.warn(instanceSettings.common.name + ': ' + err)
            res.redirect(sTarget)
         })
      })
      
      adapter.log.info('Google Authentication is ready')
   }

   isTrue(vValue){
      return vValue === 'true' || vValue === true || vValue === 'on'
   }
}

module.exports = WebExtension