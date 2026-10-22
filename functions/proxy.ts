
const DEFAULT_API_BASE_URL = "https://music.gdstudio.xyz/api.php";
const KUWO_HOST_PATTERN = /(^|\.)kuwo\.cn\$/i;
const SAFE_RESPONSE_HEADERS = ["content-type", "cache-control", "accept-ranges", "content-length", "content-range", "etag", "last-modified", "expires"];

// --- ?? 新增：严格对齐 JavaScript 的 encodeURIComponent 规则 ---
function jsEncodeURIComponent(str: string): string {
  return encodeURIComponent(str)
    .replace(/[( )]/g, (c) => c === '(' ? '%28' : '%29')
    .replace(/\*/g, '%2A')
    .replace(/'/g, '%27')
    .replace(/!/g, '%21');
}

// --- ?? 新增：使用原生的 Web Crypto API 计算标准的 MD5 ---
async function cryptoMd5(message: string): Promise<string> {
  const msgUint8 = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest('MD5', msgUint8);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// --- ?? 新增：从上游获取实时服务器时间，动态组装盐值并算出最终的签名 s ---
async function getDynamicSign(keyword: string, apiBaseUrl: string): Promise<string> {
  // 解析出基础域名，通常是 music.gdstudio.xyz 或 music-api.gdstudio.xyz
  let host = "music.gdstudio.xyz";
  try {
    const parsedBase = new URL(apiBaseUrl);
    host = parsedBase.hostname;
  } catch {
    // fallback
  }

  const VERSION = "2026.09.25"; 
  const versionText = VERSION.split('.').map(p => p.padStart(2, '0')).join('');

  try {
    // 1. 同步请求上游服务器的时间接口
    const timeResponse = await fetch(`https://${host}/time`);
    const timeText = await timeResponse.text();
    const serverTime = timeText.trim().substring(0, 9);

    // 2. 拼接盐值
    const encodedKeyword = jsEncodeURIComponent(keyword);
    const saltString = `${serverTime}|${host}|${versionText}|${encodedKeyword}`;

    // 3. 计算 MD5 截取大写后 8 位
    const md5Hex = await cryptoMd5(saltString);
    return md5Hex.substring(md5Hex.length - 8).toUpperCase();
  } catch (e) {
    console.warn(`[Sign Error] Failed to get server time, falling back to local time.`, e);
    // 容灾：如果目标服务器 time 接口挂了，降级用当前边缘节点时间算
    const localTime = Math.floor(Date.now() / 1000).toString().substring(0, 9);
    const encodedKeyword = jsEncodeURIComponent(keyword);
    const saltString = `${localTime}|${host}|${versionText}|${encodedKeyword}`;
    const md5Hex = await cryptoMd5(saltString);
    return md5Hex.substring(md5Hex.length - 8).toUpperCase();
  }
}

function createCorsHeaders(init?: Headers): Headers {
  const headers = new Headers();
  if (init) {
    for (const [key, value] of init.entries()) {
      if (SAFE_RESPONSE_HEADERS.includes(key.toLowerCase())) {
        headers.set(key, value);
      }
    }
  }
  if (!headers.has("Cache-Control")) {
    headers.set("Cache-Control", "no-store");
  }
  headers.set("Access-Control-Allow-Origin", "*");
  return headers;
}

function handleOptions(): Response {
  return new Response(null, {
    status: 204,
    headers: {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET,HEAD,OPTIONS",
      "Access-Control-Allow-Headers": "*",
      "Access-Control-Max-Age": "86400",
    },
  });
}

function isAllowedKuwoHost(hostname: string): boolean {
  if (!hostname) return false;
  return KUWO_HOST_PATTERN.test(hostname);
}

function normalizeKuwoUrl(rawUrl: string): URL | null {
  try {
    const parsed = new URL(rawUrl);
    if (!isAllowedKuwoHost(parsed.hostname)) {
      return null;
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      return null;
    }
    parsed.protocol = "http:";
    return parsed;
  } catch {
    return null;
  }
}

async function proxyKuwoAudio(targetUrl: string, request: Request): Promise<Response> {
  const normalized = normalizeKuwoUrl(targetUrl);
  if (!normalized) {
    return new Response("Invalid target", { status: 400 });
  }

  const init: RequestInit = {
    method: request.method,
    headers: {
      "User-Agent": request.headers.get("User-Agent") ?? "Mozilla/5.0",
      "Referer": "https://www.kuwo.cn/",
    },
  };

  const rangeHeader = request.headers.get("Range");
  if (rangeHeader) {
    (init.headers as Record<string, string>)["Range"] = rangeHeader;
  }

  const upstream = await fetch(normalized.toString(), init);
  const headers = createCorsHeaders(upstream.headers);
  if (!headers.has("Cache-Control")) {
    headers.set("Cache-Control", "public, max-age=3600");
  }

  return new Response(upstream.body, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers,
  });
}

async function proxyApiRequest(url: URL, request: Request, waitUntil?: (promise: Promise<any>) => void, apiBaseUrl: string = DEFAULT_API_BASE_URL): Promise<Response> {
  const cache = caches.default;
  
  // 构建缓存 Key（过滤掉随机签名 s 以及强制刷新标记 nocache，以便重试成功后能更新同一个缓存项）
  const cacheUrl = new URL(url.toString());
  cacheUrl.searchParams.delete("s");
  cacheUrl.searchParams.delete("nocache");
  
  const cacheKey = new Request(cacheUrl.toString(), {
    method: request.method,
    headers: request.headers
  });

  // 如果是 GET 请求且未指定 nocache 强制刷新，尝试命中缓存
  const bypassCache = url.searchParams.get("nocache") === "true";
  if (request.method === "GET" && !bypassCache) {
    try {
      const cachedResponse = await cache.match(cacheKey);
      if (cachedResponse) {
        console.log(`[Cache HIT] ${url.toString()}`);
        const response = new Response(cachedResponse.body, cachedResponse);
        response.headers.set("X-Cache-Status", "HIT");
        response.headers.set("Access-Control-Expose-Headers", "X-Cache-Status");
        return response;
      }
    } catch (err) {
      console.warn(`[Cache ERROR] ${url.toString()}`, err);
    }
  }

  console.log(`[Cache MISS] Fetching from upstream: ${url.toString()}`);

  const apiUrl = new URL(apiBaseUrl);
  url.searchParams.forEach((value, key) => {
    // 这里拦截掉前端可能传来的过期或无用的 s 和其它特殊 key
    if (key === "target" || key === "callback" || key === "s" || key === "nocache") {
      return;
    }
    apiUrl.searchParams.set(key, value);
  });

  if (!apiUrl.searchParams.has("types")) {
    return new Response("Missing types", { status: 400 });
  }

  // === ??? 核心改动：在向上游 fetch 之前，现场根据当前关键词动态算一个全新的 s ===
  const keyword = url.searchParams.get('name') || '';
  const dynamicS = await getDynamicSign(keyword, apiBaseUrl);
  apiUrl.searchParams.set('s', dynamicS); // 强势注入最新合法 s 验证参数

  const upstream = await fetch(apiUrl.toString(), {
    headers: {
      "User-Agent": "Meting/1.5.0",
      "Accept": "application/json",
      "Referer": `https://${apiUrl.hostname}/`,
      "X-Requested-With": "XMLHttpRequest"
    },
  });

  const responseText = await upstream.text();
  const headers = createCorsHeaders(upstream.headers);
  if (!headers.has("Content-Type")) {
    headers.set("Content-Type", "application/json; charset=utf-8");
  }

  headers.set("X-Cache-Status", "MISS");
  headers.set("Access-Control-Expose-Headers", "X-Cache-Status");

  // 判断是否应该缓存：必须是 200 状态，且内容不能是空数组或包含错误标识，且未指定强制刷新
  const isSearch = url.searchParams.get("types") === "search";
  const isEmptyResult = responseText.trim() === "[]";
  const isError = responseText.includes('"error"') || responseText.includes('"status":0');
  
  let shouldCache = upstream.status === 200 && request.method === "GET" && !isError && !bypassCache;
  
  // 如果是搜索请求且结果为空，通常是 API 繁忙或异常，不建议长缓存
  if (isSearch && isEmptyResult) {
    shouldCache = false;
  }

  if (shouldCache) {
    headers.set("Cache-Control", "public, s-maxage=300, max-age=300");
  } else {
    headers.set("Cache-Control", "no-store, no-cache, must-revalidate");
  }

  const response = new Response(responseText, {
    status: upstream.status,
    statusText: upstream.statusText,
    headers,
  });

  // 写入缓存（不阻塞主流程）
  if (shouldCache && waitUntil) {
    waitUntil(cache.put(cacheKey, response.clone()));
    console.log(`[Cache PUT] Saved to cache: ${url.toString()}`);
  }

  return response;
}

export async function onRequest({ request, waitUntil, env }: { request: Request, waitUntil: (promise: Promise<any>) => void, env: any }): Promise<Response> {
  // 优先使用环境变量中配置的 API 地址，CF 部署未设置时 fallback 到默认节点
  const apiBaseUrl = (typeof env?.API_BASE_URL === "string" && env.API_BASE_URL) ? env.API_BASE_URL : DEFAULT_API_BASE_URL;
  if (request.method === "OPTIONS") {
    return handleOptions();
  }

  if (request.method !== "GET" && request.method !== "HEAD") {
    return new Response("Method not allowed", { status: 405 });
  }

  const url = new URL(request.url);
  const target = url.searchParams.get("target");

  if (target) {
    return proxyKuwoAudio(target, request);
  }

  return proxyApiRequest(url, request, waitUntil, apiBaseUrl);
}
