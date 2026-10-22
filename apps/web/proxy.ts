import { NextResponse, type NextRequest } from "next/server";

// Cheap gate: send visitors without a session cookie to the login page. This is a convenience only;
// the API validates the session on every request and is the real enforcement point.
const PUBLIC = ["/login", "/register"];

export function proxy(req: NextRequest) {
  const { pathname } = req.nextUrl;
  if (PUBLIC.some((p) => pathname.startsWith(p))) return NextResponse.next();
  const cookie = process.env.SESSION_COOKIE_NAME || "veylith_session";
  if (!req.cookies.get(cookie)) {
    const url = req.nextUrl.clone();
    url.pathname = "/login";
    url.search = "";
    return NextResponse.redirect(url);
  }
  return NextResponse.next();
}

export const config = { matcher: ["/((?!api|_next/static|_next/image|favicon.ico).*)"] };
