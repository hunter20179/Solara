const PUBLIC_PATH_PATTERNS = [/^\/login(?:\/|\()/, /^\/api\/login(?:\/\vert{}\))/];
const PUBLIC_FILE_EXTENSIONS = new Set([
  ".css",
  ".js",
  ".png",
  ".svg",
  ".jpg",
  ".jpeg",
  ".gif",
  ".webp",
  ".ico",
  ".txt",
  ".map",
  ".json",
  ".woff",
  ".woff2",
]);

// ==================== ⚙️ 新增：严格对齐 JavaScript 的 encodeURIComponent 规则 ====================
function jsEncodeURIComponent(str: string): string {
  return encodeURIComponent(str)
    .replace(/[( )]/g, (c) => c === '(' ? '%28' : '%29')
    .replace(/\*/g, '%2A')
    .replace(/'/g, '%27')
    .replace(/!/g, '%21');
}

// ==================== ⚙️ 新增：使用原生的 Web Crypto API 计算标准的 MD5 ====================
async function cryptoMd5(message: string): Promise<string> {
  const msgUint8 = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest('MD5', msgUint8);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// ==================== ⚙️ 新增：动态请求上游获取服务器时间，现场计算 8 位合法 s 参数 ====================
async function getDynamicSign(keyword: string, host: string): Promise<string> {
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
    // 容灾：如果上游挂了，用当前边缘节点时间算
    const localTime = Math.floor(Date.now() / 1000).toString().substring(0, 9);
    const saltString = `${localTime}|${host}|${versionText}|${jsEncodeURIComponent(keyword)}`;
    const md5Hex = await cryptoMd5(saltString);
    return md5Hex.substring(md5Hex.length - 8).toUpperCase();
  }
}

// ==================== ⚙️ 新增：专门拦截 API 请求、改写 s 参数的签名中间件 ====================
async function signMiddleware(context: any) {
  const { request } = context;
  const url = new URL(request.url);

  // 只要是发往本地代理接口的请求，在最前端完成 s 的强制重写和注入
  if (url.pathname.includes('/proxy') || url.pathname.includes('/api/')) {
    const targetHost = "music.gdstudio.xyz";
    const keyword = url.searchParams.get('name') || url.searchParams.get('keyword') || '';
    
    // 现场计算最新合法的 8 位 s 校验码
    const dynamicS = await getDynamicSign(keyword, targetHost);

    // 重新构造一个新的 URL，强行抹除前端传过来的 22 位错误 s，并打入新的 s
    const modifiedUrl = new URL(request.url);
    modifiedUrl.searchParams.set('s', dynamicS);

    // 覆盖 context 里的旧 request
    context.request = new Request(modifiedUrl.toString(), {
      method: request.method,
      headers: request.headers,
      body: request.body,
    });
  }

  // 顺畅地移交给下一个中间件（即原版的权限校验）
  return context.next();
}

function hasPublicExtension(pathname: string): boolean {
  const lastDotIndex = pathname.lastIndexOf(".");
  if (lastDotIndex === -1) {
    return false;
  }
  const extension = pathname.slice(lastDotIndex).toLowerCase();
  return PUBLIC_FILE_EXTENSIONS.has(extension);
}

function isPublicPath(pathname: string): boolean {
  return (
    PUBLIC_PATH_PATTERNS.some((pattern) => pattern.test(pathname)) ||
    hasPublicExtension(pathname)
  );
}

async function authMiddleware(context: any) {
  const { request, env } = context;
  const password = env.PASSWORD;

  if (typeof password !== "string") {
    return context.next();
  }

  const url = new URL(request.url);
  if (url.hostname === "127.0.0.1" || url.hostname === "localhost") {
    return context.next();
  }

  const pathname = url.pathname;
  if (isPublicPath(pathname)) {
    return context.next();
  }

  const cookieHeader = request.headers.get("Cookie") || "";
  const cookies: Record<string, string> = {};
  cookieHeader.split(";").forEach((part) => {
    const separatorIndex = part.indexOf("=");
    if (separatorIndex === -1) {
      return;
    }
    const key = part.slice(0, separatorIndex).trim();
    const value = part.slice(separatorIndex + 1).trim();
    if (key) {
      cookies[key] = value;
    }
  });

  if (cookies.auth && cookies.auth === btoa(password)) {
    return context.next();
  }

  if (pathname.startsWith("/proxy") || pathname.startsWith("/api/") || pathname.startsWith("/palette")) {
    return new Response(JSON.stringify({ error: "Unauthorized", message: "Login required" }), {
      status: 401,
      headers: { "Content-Type": "application/json; charset=utf-8" },
    });
  }

  const loginUrl = new URL("/login", url);
  return Response.redirect(loginUrl.toString(), 302);
}

async function i18nMiddleware(context: any) {
  const { env, next } = context;
  const response = await next();
  const language = env.language || env.LANGUAGE;
  
  if (language === "ENG" && response.headers.get("content-type")?.includes("text/html")) {
    return new HTMLRewriter().on("head", {
      element(element: any) {
        element.prepend(`<script>window.SITE_LANGUAGE = "ENG";</script>`, { html: true });
      }
    }).transform(response);
  }
  
  return response;
}

// === 🚀 核心修改：将我们写的 signMiddleware 拦截器，追加在最开始位置运行 ===
export const onRequest = [signMiddleware, authMiddleware, i18nMiddleware];
