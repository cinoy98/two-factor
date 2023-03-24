
import {
    html,
    render
  } from "https://unpkg.com/lit-html@1.0.0/lit-html.js?module";
  
  const notConfiguredHtml = html`
    <p>
      ✖️ Two-factor authentication is not configured 
    </p>
  `;
  
  const configuredHtml = html`
    <p>
      ✅ Two-factor authentication with a security key is configured
    </p>
  `;
  
  const getTitleHtml = credentialsCount => html`
    <h4>
      Credential${credentialsCount > 1 ? "s" : ""} (${credentialsCount})
    </h4>
  `;
  
  function getCredentialHtml(credential, removeEl, renameEl) {
    const { name, credId, publicKey, creationDate } = credential;
    return html`
      <div class="credential-card">
        <div class="credential-name">
          ${name
            ? html`
                ${name}
              `
            : html`
                <span class="unnamed">(Unnamed)</span>
              `}
        </div>
        <div>
          <label>Created:</label>
          <div class="info">
            ${new Date(creationDate).toLocaleDateString()}
            ${new Date(creationDate).toLocaleTimeString()}
          </div>
        </div>
        <div class="flex-end">
          <button
            data-credential-id="${credId}"
            data-credential-name="${name}"
            @click="${renameEl}"
            class="secondary right"
          >
            ✏️ Rename
          </button>
          <button
            data-credential-id="${credId}"
            @click="${removeEl}"
            class="secondary remove right"
          >
            🗑 Remove
          </button>
        </div>
      </div>
    `;
  }
  
  function getCredentialListHtml(credentials, removeEl, renameEl) {
    return html`
      ${credentials.length
        ? html`
            ${configuredHtml} ${getTitleHtml(credentials.length)}
            ${credentials.map(
              cred => html`
                ${getCredentialHtml(cred, removeEl, renameEl)}
              `
            )}
          `
        : notConfiguredHtml}
    `;
  }
  
  export { getCredentialListHtml };
  