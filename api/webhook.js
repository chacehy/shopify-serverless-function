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

/**
 * Minimal HTTPS GraphQL client for Shopify Admin API.
 */
function shopifyRequestGraphQL({ storeDomain, apiVersion, token, query, variables = undefined }) {
  return new Promise((resolve, reject) => {
    const requestPath = `/admin/api/${apiVersion}/graphql.json`;
    const options = {
      hostname: storeDomain,
      method: 'POST',
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
          return reject(new Error(`Failed to parse GraphQL JSON response (${statusCode}): ${text}`));
        }
        if (statusCode >= 200 && statusCode < 300) {
          if (parsed && parsed.errors) {
            const error = new Error(`Shopify GraphQL errors: ${JSON.stringify(parsed.errors)}`);
            error.body = parsed;
            return reject(error);
          }
          return resolve(parsed);
        } else {
          const error = new Error(`Shopify API POST ${requestPath} failed (${statusCode}): ${text}`);
          error.statusCode = statusCode;
          error.body = parsed;
          return reject(error);
        }
      });
    });
    req.setTimeout(requestTimeoutMs, () => {
      req.destroy(new Error(`Request timed out after ${requestTimeoutMs}ms`));
    });
    req.on('error', (err) => reject(err));
    req.write(JSON.stringify({ query, variables }));
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

function escapeForQuery(value) {
  return String(value || '').replace(/"/g, '\\"').trim();
}

async function findVariantByTitles({ storeDomain, apiVersion, token, productTitle, variantTitle }) {
  const productTitleEscaped = escapeForQuery(productTitle);
  const variantTitleEscaped = escapeForQuery(variantTitle);
  const parts = [];
  if (productTitleEscaped) parts.push(`product_title:\"${productTitleEscaped}\"`);
  if (variantTitleEscaped) parts.push(`title:\"${variantTitleEscaped}\"`);
  const searchQuery = parts.join(' AND ');
  const query = `query($first:Int!, $query:String!){\n    productVariants(first:$first, query:$query){\n      edges{ node{ id title sku product{ title } inventoryItem{ id } } }\n    }\n  }`;
  const resp = await shopifyRequestGraphQL({
    storeDomain,
    apiVersion,
    token,
    query,
    variables: { first: 10, query: searchQuery },
  });
  const edges = resp && resp.data && resp.data.productVariants && resp.data.productVariants.edges ? resp.data.productVariants.edges : [];
  if (!edges.length) return null;
  const node = edges[0].node;
  const invGid = node && node.inventoryItem && node.inventoryItem.id;
  const inventoryItemId = invGid ? String(invGid).split('/').pop() : null;
  return inventoryItemId ? { inventory_item_id: Number(inventoryItemId) } : null;
}

async function findProductByInventoryItemId({ storeDomain, apiVersion, token, inventoryItemId }) {
  const query = `query($first:Int!, $query:String!){\n    productVariants(first:$first, query:$query){\n      edges{ node{ id title sku product{ title } inventoryItem{ id } } }\n    }\n  }`;
  const searchQuery = `inventory_item_id:${inventoryItemId}`;
  const resp = await shopifyRequestGraphQL({
    storeDomain,
    apiVersion,
    token,
    query,
    variables: { first: 10, query: searchQuery },
  });
  const edges = resp && resp.data && resp.data.productVariants && resp.data.productVariants.edges ? resp.data.productVariants.edges : [];
  if (!edges.length) return null;
  const node = edges[0].node;
  return {
    productTitle: node.product && node.product.title,
    variantTitle: node.title,
    sku: node.sku,
    inventoryItemId: inventoryItemId
  };
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

async function setInventoryLevel({ storeDomain, apiVersion, token, inventoryItemId, locationId, available }) {
  return shopifyRequestJSON({
    storeDomain,
    apiVersion,
    method: 'POST',
    path: '/inventory_levels/set',
    token,
    body: {
      inventory_item_id: inventoryItemId,
      location_id: locationId,
      available: available,
    },
  });
}

async function handleInventoryLevelUpdate(payload, sourceStore, config, res) {
  const { b2cDomain, b2bDomain, b2cToken, b2bToken, b2cApiVersion, b2bApiVersion, b2cLocationIdEnv, b2bLocationIdEnv } = config;
  
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

  // Extract inventory level data from payload
  // For inventory_levels/update webhooks, the data is directly in the payload
  const inventoryItemId = payload && payload.inventory_item_id;
  const available = payload && payload.available;
  const locationId = payload && payload.location_id;

  if (!inventoryItemId || typeof available !== 'number') {
    console.log('Invalid inventory level data in payload:', { inventoryItemId, available, locationId });
    return res.status(200).send('OK');
  }

  try {
    // Get product information from source store
    const sourceStoreConfig = sourceStore === 'b2c'
      ? { storeDomain: b2cDomain, apiVersion: b2cApiVersion, token: b2cToken }
      : { storeDomain: b2bDomain, apiVersion: b2bApiVersion, token: b2bToken };

    const productInfo = await findProductByInventoryItemId({
      ...sourceStoreConfig,
      inventoryItemId
    });

    if (!productInfo || !productInfo.productTitle) {
      console.warn(`No product found for inventory_item_id ${inventoryItemId} in ${sourceStore}`);
      return res.status(200).send('OK');
    }

    console.log(`Inventory level updated in ${sourceStore}:`, {
      productTitle: productInfo.productTitle,
      variantTitle: productInfo.variantTitle,
      sku: productInfo.sku,
      available: available
    });

    // Find matching product in target store by title
    const targetVariant = await findVariantByTitles({
      storeDomain: target.storeDomain,
      apiVersion: target.apiVersion,
      token: target.token,
      productTitle: productInfo.productTitle,
      variantTitle: productInfo.variantTitle,
    });

    if (!targetVariant) {
      console.warn(`No matching variant found in ${target.label} for product "${productInfo.productTitle}" variant "${productInfo.variantTitle}"`);
      return res.status(200).send('OK');
    }

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

    // Set inventory level in target store
    const setResponse = await setInventoryLevel({
      storeDomain: target.storeDomain,
      apiVersion: target.apiVersion,
      token: target.token,
      inventoryItemId: targetVariant.inventory_item_id,
      locationId: targetLocationId,
      available: available,
    });

    const newAvailable = setResponse && setResponse.inventory_level && typeof setResponse.inventory_level.available === 'number'
      ? setResponse.inventory_level.available
      : undefined;

    console.log(`Synced inventory level for product "${productInfo.productTitle}" variant "${productInfo.variantTitle || 'Default'}" to ${available} in ${target.label}` + (newAvailable !== undefined ? `; confirmed available: ${newAvailable}` : ''));

  } catch (error) {
    console.error('Inventory level sync failed', error);
    // Still acknowledge to Shopify to avoid retries storm; log for investigation
  }

  return res.status(200).send('OK');
}

module.exports = async (req, res) => {
  console.log('🚀 Webhook function called:', {
    method: req.method,
    headers: {
      'x-shopify-topic': req.headers['x-shopify-topic'],
      'x-shopify-shop-domain': req.headers['x-shopify-shop-domain'],
      'x-shopify-hmac-sha256': req.headers['x-shopify-hmac-sha256'] ? 'present' : 'missing'
    }
  });

  if (req.method !== 'POST') {
    res.setHeader('Allow', 'POST');
    return res.status(405).send('Method Not Allowed');
  }

  const b2cDomain = (process.env.B2C_SHOPIFY_STORE_URL || '').toLowerCase();
  const b2bDomain = (process.env.B2B_SHOPIFY_STORE_URL || '').toLowerCase();
  const b2cSecret = process.env.B2C_SHOPIFY_API_SECRET;
  const b2bSecret = process.env.B2B_SHOPIFY_API_SECRET;
  const b2cWebhookSecret = process.env.B2C_SHOPIFY_WEBHOOK_SECRET || b2cSecret;
  const b2bWebhookSecret = process.env.B2B_SHOPIFY_WEBHOOK_SECRET || b2bSecret;
  const b2cToken = process.env.B2C_SHOPIFY_ADMIN_API_TOKEN;
  const b2bToken = process.env.B2B_SHOPIFY_ADMIN_API_TOKEN;
  const b2cApiVersion = process.env.B2C_SHOPIFY_API_VERSION || '2023-04';
  const b2bApiVersion = process.env.B2B_SHOPIFY_API_VERSION || '2023-04';
  const b2cLocationIdEnv = process.env.B2C_SHOPIFY_LOCATION_ID;
  const b2bLocationIdEnv = process.env.B2B_SHOPIFY_LOCATION_ID;

  if (!b2cSecret || !b2bSecret || !b2cToken || !b2bToken || !b2cDomain || !b2bDomain) {
    console.error('❌ Missing environment variables:', {
      b2cDomain: !!b2cDomain,
      b2bDomain: !!b2bDomain,
      b2cSecret: !!b2cSecret,
      b2bSecret: !!b2bSecret,
      b2cToken: !!b2cToken,
      b2bToken: !!b2bToken
    });
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
  if (incomingShop === b2cDomain && isValidShopifyHmac(rawBody, hmacHeader, b2cWebhookSecret)) {
    sourceStore = 'b2c';
  } else if (incomingShop === b2bDomain && isValidShopifyHmac(rawBody, hmacHeader, b2bWebhookSecret)) {
    sourceStore = 'b2b';
  } else {
    // Fallback: try both secrets in case domain header is unexpected
    if (isValidShopifyHmac(rawBody, hmacHeader, b2cWebhookSecret)) {
      sourceStore = 'b2c';
    } else if (isValidShopifyHmac(rawBody, hmacHeader, b2bWebhookSecret)) {
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

  // Handle order events and inventory level updates
  const normalizedTopic = (topic || '').toLowerCase();
  const isCreate = normalizedTopic === 'orders/create';
  const isCancelled = normalizedTopic === 'orders/cancelled';
  const isInventoryUpdate = normalizedTopic === 'inventory_levels/update';
  
  if (!isCreate && !isCancelled && !isInventoryUpdate) {
    return res.status(200).send('Ignored');
  }
  
  // Handle inventory level updates separately
  if (isInventoryUpdate) {
    return await handleInventoryLevelUpdate(payload, sourceStore, {
      b2cDomain, b2bDomain, b2cToken, b2bToken, b2cApiVersion, b2bApiVersion,
      b2cLocationIdEnv, b2bLocationIdEnv
    }, res);
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

  // Aggregate quantities per product/variant titles to minimize API calls
  const titleToQuantity = {};
  const lineItems = Array.isArray(payload && payload.line_items) ? payload.line_items : [];
  for (const item of lineItems) {
    const productTitle = (item && item.title) || '';
    const variantTitle = (item && item.variant_title) || '';
    const quantity = Number(item && item.quantity) || 0;
    if (!productTitle || quantity <= 0) continue;
    const key = `${productTitle}||${variantTitle}`;
    titleToQuantity[key] = (titleToQuantity[key] || 0) + quantity;
  }

  if (Object.keys(titleToQuantity).length === 0) {
    console.log('No line items with quantity to adjust.');
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
    console.log(`Using target location ${targetLocationId} on ${target.label} (${target.storeDomain})`);

    // Process per-title adjustments with limited concurrency to fit time budgets
    const doAdjustForTitles = async (productTitle, variantTitle, qty) => {
      const variant = await findVariantByTitles({
        storeDomain: target.storeDomain,
        apiVersion: target.apiVersion,
        token: target.token,
        productTitle,
        variantTitle,
      });
      if (!variant) {
        console.warn(`No matching variant found in ${target.label} for product title "${productTitle}" variant title "${variantTitle}"`);
        return;
      }
      const inventoryItemId = variant.inventory_item_id;
      if (!inventoryItemId) {
        console.warn(`Variant for product title "${productTitle}" variant title "${variantTitle}" has no inventory_item_id in ${target.label}`);
        return;
      }
      const adjustment = adjustmentSign * Math.abs(qty);
      const adjustResponse = await adjustInventory({
        storeDomain: target.storeDomain,
        apiVersion: target.apiVersion,
        token: target.token,
        inventoryItemId,
        locationId: targetLocationId,
        adjustment,
      });
      const newAvailable = adjustResponse && adjustResponse.inventory_level && typeof adjustResponse.inventory_level.available === 'number'
        ? adjustResponse.inventory_level.available
        : undefined;
      console.log(`Adjusted inventory for product "${productTitle}" variant "${variantTitle || 'Default'}" by ${adjustment} in ${target.label} due to ${normalizedTopic}` + (newAvailable !== undefined ? `; new available: ${newAvailable}` : ''));
    };

    const entries = Object.entries(titleToQuantity);
    const concurrencyLimit = Math.max(1, Math.min(entries.length, Number(process.env.INVENTORY_ADJUST_CONCURRENCY || 5)));
    let cursor = 0;
    const runners = Array.from({ length: concurrencyLimit }, async () => {
      while (cursor < entries.length) {
        const myIndex = cursor++;
        const [key, qty] = entries[myIndex];
        const [productTitle, variantTitle] = String(key).split('||');
        try {
          await doAdjustForTitles(productTitle, variantTitle, qty);
        } catch (err) {
          console.error(`Failed to adjust inventory for product "${productTitle}" variant "${variantTitle}" in ${target.label}`, err && err.body ? err.body : err);
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

