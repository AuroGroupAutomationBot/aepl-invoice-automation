const { onDocumentCreated } = require("firebase-functions/v2/firestore");
const logger = require("firebase-functions/logger");
const admin = require("firebase-admin");
const https = require("https");

admin.initializeApp();

/**
 * Firebase Cloud Function: Automated Failure Alert Email Dispatcher
 * Trigger: Cloud Firestore document created in 'mail/{mailId}' (Mumbai asia-south1)
 * Compatible with Official Firebase Extension: firestore-send-email
 * Reference: https://firebase.google.com/docs/extensions/official/firestore-send-email
 */
exports.sendFailureEmail = onDocumentCreated(
  {
    document: "mail/{mailId}",
    region: "asia-south1",
  },
  async (event) => {
    const snap = event.data;
    if (!snap) return;

    const mailData = snap.data();
    const recipient = (mailData.to && mailData.to[0]) || "aic1176@aurogroup.com";
    const sender = mailData.from || process.env.ALERT_SENDER_EMAIL || recipient;
    const subject = mailData.message?.subject || "[SAP AP FAILURE ALERT] Automated Notification";
    const htmlBody = mailData.message?.html || mailData.message?.text || "<p>Failure incident occurred.</p>";
    const textBody = mailData.message?.text || "Failure incident occurred.";
    const incidentId = mailData.incident_id || event.params.mailId;

    logger.info(`Firestore 'mail' document created: ${incidentId} for ${recipient}`);

    // Option 1: Brevo REST API (Sendinblue Free Tier: 300 emails/day forever)
    const brevoApiKey = process.env.BREVO_API_KEY;
    if (brevoApiKey) {
      try {
        await forwardToBrevo(brevoApiKey, sender, recipient, subject, htmlBody, textBody);
        await snap.ref.update({
          delivery: {
            state: "SUCCESS",
            attempts: 1,
            endTime: new Date().toISOString(),
            provider: "Brevo REST API",
          },
        });
        logger.info(`Alert successfully dispatched via Brevo REST API.`);
        return;
      } catch (err) {
        logger.error(`Brevo API error: ${err.message}`);
      }
    }

    // Option 2: Webhook Forwarder (Power Automate, Google Chat, Teams, Slack)
    const webhookUrl = process.env.ALERT_WEBHOOK_URL;
    if (webhookUrl) {
      try {
        await forwardToWebhook(webhookUrl, {
          incident_id: incidentId,
          recipient: recipient,
          subject: subject,
          html: htmlBody,
          text: textBody,
          timestamp: mailData.timestamp || new Date().toISOString(),
        });
        await snap.ref.update({
          delivery: {
            state: "SUCCESS",
            attempts: 1,
            endTime: new Date().toISOString(),
            provider: "Webhook Forwarder",
          },
        });
        logger.info(`Alert successfully forwarded via Webhook.`);
        return;
      } catch (err) {
        logger.error(`Webhook forward error: ${err.message}`);
      }
    }

    // Option 3: Document processed by official Firebase Extension (firestore-send-email)
    logger.info(
      `Document ${incidentId} ready in 'mail' collection. The official Firebase Extension (firestore-send-email) will deliver this email.`
    );
  }
);

function forwardToBrevo(apiKey, fromEmail, toEmail, subject, htmlContent, textContent) {
  return new Promise((resolve, reject) => {
    const postData = JSON.stringify({
      sender: { email: fromEmail, name: "AEPL SAP Invoice System" },
      to: [{ email: toEmail }],
      subject: subject,
      htmlContent: htmlContent,
      textContent: textContent,
    });

    const options = {
      hostname: "api.brevo.com",
      path: "/v3/smtp/email",
      method: "POST",
      headers: {
        "api-key": apiKey,
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(postData),
      },
    };

    const req = https.request(options, (res) => {
      let body = "";
      res.on("data", (chunk) => { body += chunk; });
      res.on("end", () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve();
        } else {
          reject(new Error(`Brevo API returned status ${res.statusCode}: ${body}`));
        }
      });
    });

    req.on("error", (e) => reject(e));
    req.write(postData);
    req.end();
  });
}

function forwardToWebhook(urlStr, payload) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlStr);
    const postData = JSON.stringify(payload);
    const options = {
      hostname: url.hostname,
      port: url.port || 443,
      path: url.pathname + url.search,
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(postData),
      },
    };

    const req = https.request(options, (res) => {
      if (res.statusCode >= 200 && res.statusCode < 300) {
        resolve();
      } else {
        reject(new Error(`Webhook returned status ${res.statusCode}`));
      }
    });

    req.on("error", (e) => reject(e));
    req.write(postData);
    req.end();
  });
}
