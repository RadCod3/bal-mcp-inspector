import { useCallback, useEffect, useState } from "react";

// /api, /callback and /cimd are proxied to the backend, so app routes must stay clear of them.
export type View = "requests" | "tools";

export type Route =
  | { page: "home" }
  | { page: "new" }
  | { page: "connection"; connectionId: string; view: View }
  | { page: "edit"; connectionId: string };

export function parseRoute(pathname: string): Route {
  const segments = pathname.split("/").filter(Boolean).map(decodeURIComponent);
  if (segments[0] === "new" && segments.length === 1) return { page: "new" };
  if (segments[0] === "connections" && segments[1] && segments[2] === "edit" && segments.length === 3) {
    return { page: "edit", connectionId: segments[1] };
  }
  if (segments[0] === "connections" && segments[1] && segments.length <= 3) {
    return { page: "connection", connectionId: segments[1], view: segments[2] === "tools" ? "tools" : "requests" };
  }
  return { page: "home" };
}

export function routePath(route: Route) {
  switch (route.page) {
    case "new":
      return "/new";
    case "connection":
      return `/connections/${encodeURIComponent(route.connectionId)}${route.view === "tools" ? "/tools" : ""}`;
    case "edit":
      return `/connections/${encodeURIComponent(route.connectionId)}/edit`;
    default:
      return "/";
  }
}

export type Navigate = (route: Route, options?: { replace?: boolean }) => void;

export function useRoute(): [Route, Navigate] {
  const [route, setRoute] = useState<Route>(() => parseRoute(window.location.pathname));

  useEffect(() => {
    const onPopState = () => setRoute(parseRoute(window.location.pathname));
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  const navigate = useCallback<Navigate>((next, options) => {
    const path = routePath(next);
    if (path !== window.location.pathname) {
      if (options?.replace) window.history.replaceState(null, "", path);
      else window.history.pushState(null, "", path);
    }
    setRoute(parseRoute(path));
  }, []);

  return [route, navigate];
}
