// Route registration. The router is deliberately tiny: createRouter() from
// ../router.js, first match wins, so register specific paths before parameterised
// ones ('/members/me' before '/members/:userId').
//
// Split mirroring the API: auth, orgs (orgs + members + effective + audit),
// invites, devices, grants, sessions. Keep the registration order here.

import { registerAuthRoutes } from './auth.js';
import { registerOrgRoutes } from './orgs.js';
import { registerInviteRoutes } from './invites.js';
import { registerDeviceRoutes } from './devices.js';
import { registerGrantRoutes } from './grants.js';
import { registerSessionRoutes } from './sessions.js';

export function registerRoutes(router, deps) {
  registerAuthRoutes(router, deps);
  registerOrgRoutes(router, deps);
  registerInviteRoutes(router, deps);
  registerDeviceRoutes(router, deps);
  registerGrantRoutes(router, deps);
  registerSessionRoutes(router, deps);
}
