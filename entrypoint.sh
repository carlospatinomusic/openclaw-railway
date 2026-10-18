#!/bin/sh
set -e

# Set Control UI allowed origins to this deployment's actual Railway domain.
# Uses $RAILWAY_PUBLIC_DOMAIN (injected by Railway at runtime) so this works
# for every deployer's own random subdomain, not just one hardcoded value.
openclaw config set gateway.controlUi.allowedOrigins "[\"https://$RAILWAY_PUBLIC_DOMAIN\"]" 2>/dev/null \
  || node dist/index.js config set gateway.controlUi.allowedOrigins "[\"https://$RAILWAY_PUBLIC_DOMAIN\"]"

# The public wrapper connects to the gateway only over loopback. Trust only
# that proxy hop; all forwarded client headers are rebuilt by wrapper/server.js.
openclaw config set gateway.trustedProxies '["127.0.0.1","::1"]' 2>/dev/null \
  || node dist/index.js config set gateway.trustedProxies '["127.0.0.1","::1"]'

# Keep the cloud gateway lean enough for Railway's 1 GB memory ceiling.
# Only load the plugins needed for the current OPEN CLAW cloud role.
openclaw config set plugins.allow '["openai","memory-core","device-pair","file-transfer","linux-node"]' 2>/dev/null \
  || node dist/index.js config set plugins.allow '["openai","memory-core","device-pair","file-transfer","linux-node"]'

# Browser/computer control will be added later through a dedicated node; do not
# start the cloud browser plugin on this memory-constrained gateway.
openclaw config set browser.enabled false 2>/dev/null \
  || node dist/index.js config set browser.enabled false
openclaw config set plugins.entries.browser.enabled false 2>/dev/null \
  || node dist/index.js config set plugins.entries.browser.enabled false
openclaw config set plugins.entries.cua-computer.enabled false 2>/dev/null \
  || node dist/index.js config set plugins.entries.cua-computer.enabled false


# Make the main model explicit so Control UI first-run detection recognizes a
# completed inference route instead of bouncing back to model setup.
openclaw models set openai/gpt-5.6-luna 2>/dev/null \
  || node dist/index.js models set openai/gpt-5.6-luna

# Inject the /setup banner + auto-reconnect listener into the served
# Control UI HTML. Static assets aren't on the persistent volume, so this
# file is always pristine at container start and needs re-injecting every
# boot. The exact path isn't documented, so find it by content.
INDEX_HTML=$(grep -rl "gateway-runtime" / --include="*.html" 2>/dev/null | head -1)
if [ -n "$INDEX_HTML" ]; then
  node /inject-control-ui-extras.js "$INDEX_HTML" || echo "[inject-control-ui-extras] failed, continuing without it"
else
  echo "[inject-control-ui-extras] could not locate index.html, skipping"
fi

# The wrapper (wrapper/server.js) owns the public port from here on: it
# spawns the real gateway on an internal-only port, proxies everything
# through to it, and adds the password-gated /setup page for approving new
# device pairing requests.
exec node wrapper/server.js
