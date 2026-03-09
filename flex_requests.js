import express from 'express';
import { SecretManagerServiceClient } from '@google-cloud/secret-manager';
import { ServicesClient } from '@google-cloud/run';
import axios from 'axios';

const app = express();
app.use(express.json());

const servicesClient = new ServicesClient();
const client = new SecretManagerServiceClient();

// Cache object to prevent excessive Secret Manager API calls
const secretCache = {};
let invokerCache = { members: [], lastFetched: 0 };

async function getAllowedInvokers() {
  const now = Date.now();
  if (invokerCache.members.length > 0 && (now - invokerCache.lastFetched < 300000)) {
    return invokerCache.members;
  }

  try {
    const resource = `projects/${process.env.GCP_PROJECT_ID}/locations/us-central1/services/flex-proxy-server`;
    const [policy] = await servicesClient.getIamPolicy({ resource });
    const binding = policy.bindings?.find(b => b.role === 'roles/run.invoker');
    
    invokerCache = {
      members: binding?.members || [],
      lastFetched: now
    };
    return invokerCache.members;
  } catch (err) {
    console.error("IAM Fetch Error:", err.message);
    return []; // Fallback to empty to be safe
  }
}

// Secret name can be passed as an environment variable or hardcoded here; example: secret_manager_name = FLEX_FINANCE_CORE
async function getFlexKey(secret_manager_name) {

  // Return cached key if available to reduce latency and cost
  if (secretCache[secret_manager_name]) {
    return secretCache[secret_manager_name];
  }

  const [version] = await client.accessSecretVersion({
    name: `projects/${process.env.GCP_PROJECT_ID}/secrets/${secret_manager_name}/versions/latest`,
  });

  const key = version.payload.data.toString();
  secretCache[secret_manager_name] = key; // Store in cache
  return key;
}

// --- ROUTE DEFINITIONS ---

// Middleware to extract user identity from GCP headers
app.use(async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization; // "Bearer <token>"
    
    if (!authHeader?.startsWith('Bearer ')) return res.status(401).send('Unauthorized');

    const token = authHeader.split(' ')[1];
    
    // The JWT has 3 parts: Header, Payload, Signature. We want the Payload (index 1).
    const base64Payload = token.split('.')[1];
    const payloadBuffer = Buffer.from(base64Payload, 'base64');
    const payload = JSON.parse(payloadBuffer.toString());

    console.log(`Audit: User ${payload.email} calling via Script ${payload.aud}`);

    // Authorization Check
    const allowedMembers = await getAllowedInvokers();
    const isExplicitlyAllowed = allowedMembers.includes(`user:${payload.email}`);
    // const isGroupAllowed = allowedMembers.includes(`group:flex-authorized-users@yourdomain.com`); // For future use if I want to allow a Google Group

    if (!isExplicitlyAllowed) { // (!isExplicitlyAllowed && !isGroupAllowed) 
      console.error(`Security Alert: Unauthorized access attempt by ${payload.email}`);
      return res.status(403).send('You are not a designated Flex requester.');
    } 
    // In Google ID tokens, the 'email' field contains the user's email
    req.userEmail = payload.email || payload.sub || 'unknown-identity';
    next();

  } catch (error) {
    res.status(401).send('Invalid Identity Token');
  }
});

const flexRoute = (secretName, baseUrl, forceMethod = null) => async (req, res) => {
  try {
    const pathParams = req.params.path;
    const endpoint = Array.isArray(pathParams) ? pathParams.join('/') : (pathParams || '');
    const method = forceMethod || req.method;
    
    console.log(`User: ${req.userEmail || 'unknown'} | ${method} -> ${baseUrl}/${endpoint}`);

    const apiKey = await getFlexKey(secretName);
    
    const flexResponse = await handleFlexRequest(
      baseUrl, 
      endpoint, 
      method, 
      req.query, 
      req.body, 
      apiKey
    );

    return res.status(flexResponse.status).json(flexResponse.data);
  } catch (error) {
    console.error(`Route Error: ${error.message}`);
    const status = error.response?.status || 500;
    const data = error.response?.data || { error: error.message };
    return res.status(status).json(data);
  }
};

// Finance: Strict GET
app.get('/finance-report/*path', flexRoute("FLEX_FINANCE_REPORT", process.env.BASE_URL, 'GET'));
app.get('/beta/finance-report/*path', flexRoute("FLEX_FINANCE_REPORT", process.env.BETA_BASE_URL, 'GET'));

// Inventory: All methods
app.all('/inventory/*path', flexRoute("FLEX_INVENTORY_CORE", process.env.BASE_URL));
app.all('/beta/inventory/*path', flexRoute("FLEX_INVENTORY_CORE", process.env.BETA_BASE_URL));

// Flex-LL: All methods
app.all('/flex-ll/*path', flexRoute("FLEX_LL_CORE", process.env.BASE_URL));
app.all('/beta/flex-ll/*path', flexRoute("FLEX_LL_CORE", process.env.BETA_BASE_URL));

// --- HELPER SERVICE ---
async function handleFlexRequest(baseUrl, endpoint, method, queryParams, body, apiKey) {
  try{
    const config = {
      method: method,
      url: `${baseUrl}/${endpoint}`,
      headers: { 
        'X-Auth-Token': apiKey,
        'Content-Type': 'application/json'
      },
      // axios handles the query object automatically, no manual string building needed
      params: queryParams, 
      data: method === 'GET' ? undefined : body,
      validateStatus: () => true,
      timeout: 20000 // 20 second timeout for GCP Cloud Functions
    };

    return await axios(config);
  } catch (error) {
    console.error("Error handling Flex request:", error);
    throw error;
  }
  
}

export { app };