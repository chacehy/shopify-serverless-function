const crypto = require('crypto');
const https = require('https');

// Reuse TCP connections for lower latency in serverless environments
const keepAliveAgent = new https.Agent({ keepAlive: true });
const requestTimeoutMs = Number(process.env.SHOPIFY_API_TIMEOUT_MS || 4000);

/**
 * Read the raw request body as a Buffer.
 */
function readRawBody(request) {
  return new Promise((resolve, reject) => {
    const bodyChunks = [];
    request.on('data', (chunk) => {
      bodyChunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    });
    request.on('end', () => {
      resolve(Buffer.concat(bodyChunks));
    });
    request.on('error', (error) => reject(error));
  });
}

/**
 * Verify the Shopify HMAC header using the shared secret and the raw body.
 */
function isValidShopifyHmac(rawBodyBuffer, hmacHeaderBase64, webhookSecret) {
  if (!hmacHeaderBase64 || !webhookSecret) return false;

  const generatedHmacBuffer = crypto
    .createHmac('sha256', webhookSecret)
    .update(rawBodyBuffer)
    .digest(); // Buffer

  let providedHmacBuffer;
  try {
    providedHmacBuffer = Buffer.from(hmacHeaderBase64, 'base64');
  } catch (_) {
    return false;
  }

  if (providedHmacBuffer.length !== generatedHmacBuffer.length) {
    return false;
  }

  try {
    return crypto.timingSafeEqual(providedHmacBuffer, generatedHmacBuffer);
  } catch (_) {
    return false;
  }
}

/**
 * Minimal HTTPS JSON client for Shopify Admin REST API.
 */
function shopifyRequestJSON({
  storeDomain,
  apiVersion,
  method,
  path,
  query = undefined,
  token,
  body = undefined,
}) {
  return new Promise((resolve, reject) => {
    const queryString = query
      ? '?' + new URLSearchParams(query).toString()
      : '';
    const requestPath = `/admin/api/${apiVersion}${path}.json${queryString}`;

    const options = {
      hostname: storeDomain,
      method,
      path: requestPath,
      headers: {
        'Content-Type': 'application/json',
        'X-Shopify-Access-Token': token,
      },
      agent: keepAliveAgent,
    };

    const req = https.request(options, (res) => {
      const statusCode = res.statusCode || 0;
      const chunks = [];
      res.on('data', (d) => chunks.push(Buffer.isBuffer(d) ? d : Buffer.from(d)));
      res.on('end', () => {
        const responseBuffer = Buffer.concat(chunks);
        const text = responseBuffer.toString('utf8');
        let parsed;
        try {
          parsed = text ? JSON.parse(text) : {};
        } catch (e) {
          return reject(new Error(`Failed to parse JSON response (${statusCode}): ${text}`));
        }
        if (statusCode >= 200 && statusCode < 300) {
          resolve(parsed);
        } else {
          const error = new Error(`Shopify API ${method} ${requestPath} failed (${statusCode}): ${text}`);
          error.statusCode = statusCode;
          error.body = parsed;
          reject(error);
        }
      });
    });
    req.setTimeout(requestTimeoutMs, () => {
      req.destroy(new Error(`Request timed out after ${requestTimeoutMs}ms`));
    });
    req.on('error', (err) => reject(err));
    if (body) {
      req.write(JSON.stringify(body));
    }
    req.end();
  });
}

async function findVariantBySku({ storeDomain, apiVersion, token, sku }) {
  const response = await shopifyRequestJSON({
    storeDomain,
    apiVersion,
    method: 'GET',
    path: '/variants',
    query: { sku },
    token,
  });
  const variants = response.variants || [];
  return variants.length > 0 ? variants[0] : null;
}

async function getDefaultLocationId({ storeDomain, apiVersion, token }) {
  const response = await shopifyRequestJSON({
    storeDomain,
    apiVersion,
    method: 'GET',
    path: '/locations',
    token,
  });
  const locations = response.locations || [];
  if (locations.length === 0) return null;
  const primary = locations.find((l) => l.primary) || locations.find((l) => l.active);
  return (primary && primary.id) || locations[0].id;
}

async function adjustInventory({ storeDomain, apiVersion, token, inventoryItemId, locationId, adjustment }) {
  return shopifyRequestJSON({
    storeDomain,
    apiVersion,
    method: 'POST',
    path: '/inventory_levels/adjust',
    token,
    body: {
      inventory_item_id: inventoryItemId,
      location_id: locationId,
      available_adjustment: adjustment,
    },
  });
}

module.exports = async (req, res) => {
  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).send('Method Not Allowed');
  }

  const b2cDomain = (process.env.B2C_SHOPIFY_STORE_URL || '').toLowerCase();
  const b2bDomain = (process.env.B2B_SHOPIFY_STORE_URL || '').toLowerCase();
  const b2cSecret = process.env.B2C_SHOPIFY_API_SECRET;
  const b2bSecret = process.env.B2B_SHOPIFY_API_SECRET;
  const b2cToken = process.env.B2C_SHOPIFY_ADMIN_API_TOKEN;
  const b2bToken = process.env.B2B_SHOPIFY_ADMIN_API_TOKEN;
  const b2cApiVersion = process.env.B2C_SHOPIFY_API_VERSION || '2023-04';
  const b2bApiVersion = process.env.B2B_SHOPIFY_API_VERSION || '2023-04';
  const b2cLocationIdEnv = process.env.B2C_SHOPIFY_LOCATION_ID;
  const b2bLocationIdEnv = process.env.B2B_SHOPIFY_LOCATION_ID;

  if (!b2cSecret || !b2bSecret || !b2cToken || !b2bToken || !b2cDomain || !b2bDomain) {
    return res.status(500).send('Shop credentials are not fully configured');
  }

  let rawBody;
  try {
    rawBody = await readRawBody(req);
  } catch (error) {
    console.error('Failed to read raw body', error);
    return res.status(400).send('Invalid body');
  }

  const hmacHeader = req.headers['x-shopify-hmac-sha256'];
  const topic = req.headers['x-shopify-topic'];
  const shop = req.headers['x-shopify-shop-domain'];
  const incomingShop = (shop || '').toLowerCase();

  let sourceStore = null; // 'b2c' or 'b2b'
  if (incomingShop === b2cDomain && isValidShopifyHmac(rawBody, hmacHeader, b2cSecret)) {
    sourceStore = 'b2c';
  } else if (incomingShop === b2bDomain && isValidShopifyHmac(rawBody, hmacHeader, b2bSecret)) {
    sourceStore = 'b2b';
  } else {
    // Fallback: try both secrets in case domain header is unexpected
    if (isValidShopifyHmac(rawBody, hmacHeader, b2cSecret)) {
      sourceStore = 'b2c';
    } else if (isValidShopifyHmac(rawBody, hmacHeader, b2bSecret)) {
      sourceStore = 'b2b';
    }
  }
  if (!sourceStore) {
    return res.status(401).send('Unauthorized');
  }

  let payload;
  try {
    payload = JSON.parse(rawBody.toString('utf8'));
  } catch (error) {
    console.error('Invalid JSON payload', error);
    return res.status(400).send('Invalid JSON');
  }

  console.log('✅ Shopify webhook verified', {
    topic: topic || null,
    shop: shop || null,
    payload,
  });

  // Only act on order creation and cancellation events
  const normalizedTopic = (topic || '').toLowerCase();
  const isCreate = normalizedTopic === 'orders/create';
  const isCancelled = normalizedTopic === 'orders/cancelled';
  if (!isCreate && !isCancelled) {
    return res.status(200).send('Ignored');
  }
  const adjustmentSign = isCreate ? -1 : 1;

  // Determine target store context (the other store)
  const target = sourceStore === 'b2c'
    ? {
        storeDomain: b2bDomain,
        apiVersion: b2bApiVersion,
        token: b2bToken,
        locationIdEnv: b2bLocationIdEnv,
        label: 'b2b',
      }
    : {
        storeDomain: b2cDomain,
        apiVersion: b2cApiVersion,
        token: b2cToken,
        locationIdEnv: b2cLocationIdEnv,
        label: 'b2c',
      };

  // Aggregate quantities per SKU to minimize API calls
  const skuToQuantity = {};
  const lineItems = Array.isArray(payload && payload.line_items) ? payload.line_items : [];
  for (const item of lineItems) {
    const sku = (item && item.sku) || '';
    const quantity = Number(item && item.quantity) || 0;
    if (!sku || quantity <= 0) continue;
    skuToQuantity[sku] = (skuToQuantity[sku] || 0) + quantity;
  }

  if (Object.keys(skuToQuantity).length === 0) {
    console.log('No SKUs with quantity to adjust.');
    return res.status(200).send('OK');
  }

  try {
    // Resolve target location id
    let targetLocationId = target.locationIdEnv;
    if (!targetLocationId) {
      targetLocationId = await getDefaultLocationId({
        storeDomain: target.storeDomain,
        apiVersion: target.apiVersion,
        token: target.token,
      });
    }
    if (!targetLocationId) {
      console.error('Unable to resolve target location id');
      return res.status(500).send('No target location available');
    }

    // Process per-SKU adjustments with limited concurrency to fit time budgets
    const doAdjustForSkuQuantity = async (sku, qty) => {
      const variant = await findVariantBySku({
        storeDomain: target.storeDomain,
        apiVersion: target.apiVersion,
        token: target.token,
        sku,
      });
      if (!variant) {
        console.warn(`No matching variant found in ${target.label} for SKU ${sku}`);
        return;
      }
      const inventoryItemId = variant.inventory_item_id;
      if (!inventoryItemId) {
        console.warn(`Variant for SKU ${sku} has no inventory_item_id in ${target.label}`);
        return;
      }
      const adjustment = adjustmentSign * Math.abs(qty);
      await adjustInventory({
        storeDomain: target.storeDomain,
        apiVersion: target.apiVersion,
        token: target.token,
        inventoryItemId,
        locationId: targetLocationId,
        adjustment,
      });
      console.log(`Adjusted inventory for SKU ${sku} by ${adjustment} in ${target.label} due to ${normalizedTopic}`);
    };

    const entries = Object.entries(skuToQuantity);
    const concurrencyLimit = Math.max(1, Math.min(entries.length, Number(process.env.INVENTORY_ADJUST_CONCURRENCY || 5)));
    let cursor = 0;
    const runners = Array.from({ length: concurrencyLimit }, async () => {
      while (cursor < entries.length) {
        const myIndex = cursor++;
        const [sku, qty] = entries[myIndex];
        try {
          await doAdjustForSkuQuantity(sku, qty);
        } catch (err) {
          console.error(`Failed to adjust inventory for SKU ${sku} in ${target.label}`, err && err.body ? err.body : err);
        }
      }
    });
    await Promise.all(runners);
  } catch (error) {
    console.error('Inventory sync failed', error);
    // Still acknowledge to Shopify to avoid retries storm; log for investigation
  }

  return res.status(200).send('OK');
};


