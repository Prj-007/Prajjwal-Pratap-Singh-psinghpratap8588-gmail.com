// A control that exists only when the server said allow. Absent otherwise — never disabled.
//
// `perms` is a resolved set from the API (org-level from login, or a device row's own set);
// this component does not know or care which role produced it.

import React from 'react';

export const allows = (perms, key) => perms?.[key]?.effect === 'allow';

export function Gated({ perms, permission, testid, children, className, ...rest }) {
  if (!allows(perms, permission)) return null;
  return (
    <button data-testid={testid} data-permission={permission} data-state="unlocked" className={className} {...rest}>
      {children}
    </button>
  );
}
