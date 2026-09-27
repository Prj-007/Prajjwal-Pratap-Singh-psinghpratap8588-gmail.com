// Route registration. The router is deliberately tiny: createRouter() from
// ../router.js, first match wins, so register specific paths before parameterised
// ones ('/members/me' before '/members/:userId').
//
// Split mirroring the API: auth, orgs (orgs + members + effective + audit),
// invites, devices (devices + grants), sessions. Keep the registration order here.

import { registerAuthRoutes } from './auth.js';

export function registerRoutes(router, deps) {
  registerAuthRoutes(router, deps);
}
