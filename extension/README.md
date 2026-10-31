# DIFF SHIELD browser extension

The extension checks the local DiffShield backend and scans GitHub pull
requests automatically when you open their pages.

## Start the backend

From the repository root, install the backend dependencies and start the API:

```bash
cd backend
python -m pip install -r requirements.txt
uvicorn main:app --host 127.0.0.1 --port 8000
```

Confirm it is available at <http://127.0.0.1:8000/health>.

## Build and load the extension

From the repository root:

```bash
cd extension
npm install
npm run build
```

Open `chrome://extensions/`, enable **Developer mode**, click **Load unpacked**,
and select `extension/dist`. After rebuilding changes, click **Reload** on the
extension card.

## Scan a pull request

With the backend running, open a GitHub pull request. The content script sends
the PR URL to the extension service worker, which requests analysis from
`http://127.0.0.1:8000/api/analyze-pr`. The worker saves the latest scan result
locally. A detected regression appears as a red banner on the PR and in the
popup; the popup also shows backend connectivity and the latest scan status.
Successful clean scans clear the previous latest-finding banner. Failed scans
are shown as errors in the popup instead of being silently dropped.

The service worker makes backend requests using the extension's declared host
permissions, so the content script does not make cross-origin requests itself.
The backend accepts only HTTPS GitHub pull-request URLs and does not follow
redirects while fetching diffs.
