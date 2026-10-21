import http from "k6/http";
import { check } from "k6";

export const options = {
  scenarios: {
    runtime_bootstrap: {
      executor: "constant-arrival-rate",
      rate: Number(__ENV.XOOS_RPS || 100),
      timeUnit: "1s",
      duration: __ENV.XOOS_DURATION || "60s",
      preAllocatedVUs: Number(__ENV.XOOS_PREALLOCATED_VUS || 100),
      maxVUs: Number(__ENV.XOOS_MAX_VUS || 300)
    }
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<1000", "p(99)<2000"]
  }
};

const baseUrl = (__ENV.XOOS_RUNTIME_URL || "").replace(/\/+$/, "");
const clientId = __ENV.XOOS_CLIENT_ID || "";
const accessToken = __ENV.XOOS_ACCESS_TOKEN || "";
const origin = __ENV.XOOS_ORIGIN || "";

export default function () {
  if (!baseUrl || !clientId || !accessToken) {
    throw new Error(
      "XOOS_RUNTIME_URL, XOOS_CLIENT_ID, and XOOS_ACCESS_TOKEN are required."
    );
  }

  const response = http.get(
    `${baseUrl}/v1/runtime/bootstrap?client_id=${encodeURIComponent(clientId)}`,
    {
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "X-XO-Client-Id": clientId,
        ...(origin ? { Origin: origin } : {})
      }
    }
  );

  check(response, {
    "bootstrap returns 200": (res) => res.status === 200,
    "bootstrap has feed": (res) => {
      try {
        return Array.isArray(res.json("feed.microapps"));
      } catch {
        return false;
      }
    }
  });
}
