#!/bin/sh
# Container entrypoint: ensure the demo-app git checkout exists, then serve.
# - DEMO_APP_PATH: where the agent expects the cloud-rca-demo-app checkout
# - DEMO_APP_REPO_URL: source to clone when the path is missing/not a repo
# - GH_TOKEN: used for authenticated clone/push when set (never echoed)
set -e

DEMO_APP_PATH="${DEMO_APP_PATH:-/tmp/demo-app}"
DEMO_APP_REPO_URL="${DEMO_APP_REPO_URL:-https://github.com/swethakambathula/cloud-rca-demo-app.git}"

needs_clone=0
if [ ! -d "$DEMO_APP_PATH/.git" ]; then
  if [ ! -e "$DEMO_APP_PATH" ] || [ -z "$(ls -A "$DEMO_APP_PATH" 2>/dev/null)" ]; then
    needs_clone=1
  else
    echo "entrypoint: WARNING $DEMO_APP_PATH exists but is not a git checkout; leaving untouched (set DEMO_APP_PATH elsewhere or empty it)"
  fi
fi

if [ "$needs_clone" = "1" ] && [ -n "$DEMO_APP_REPO_URL" ]; then
  echo "entrypoint: cloning demo app into $DEMO_APP_PATH"
  rm -rf "$DEMO_APP_PATH"
  if [ -n "$GH_TOKEN" ]; then
    # token in remote URL so later `git push` works; token never logged
    host="$(echo "$DEMO_APP_REPO_URL" | sed -e 's#https://##')"
    git clone "https://x-access-token:${GH_TOKEN}@${host}" "$DEMO_APP_PATH" 2>&1 | sed 's/x-access-token:[^@]*@/x-access-token:***@/'
  else
    git clone "$DEMO_APP_REPO_URL" "$DEMO_APP_PATH"
  fi
fi

# git identity for fix-branch commits (container-local, harmless)
git config --global user.email "${GIT_USER_EMAIL:-rca-agent@example.com}" || true
git config --global user.name "${GIT_USER_NAME:-rca-agent}" || true
git config --global --add safe.directory "$DEMO_APP_PATH" || true

if [ -d "$DEMO_APP_PATH/.git" ]; then
  echo "entrypoint: demo checkout ready at $DEMO_APP_PATH ($(git -C "$DEMO_APP_PATH" rev-parse --abbrev-ref HEAD 2>/dev/null || echo '?'))"
else
  echo "entrypoint: WARNING demo checkout unavailable at $DEMO_APP_PATH (code-fix PR flow will report prerequisites)"
fi

export DEMO_APP_PATH
PORT="${PORT:-8080}"
exec uvicorn app.main:app --host 0.0.0.0 --port "$PORT"
