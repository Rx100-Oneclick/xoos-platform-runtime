import { describe, expect, it } from "vitest";
import {
  findAuthorizedMicroapp,
  hasMicroappPermission,
  type EffectiveAuthorization
} from "./authorization";

const authorization: EffectiveAuthorization = {
  roles: ["APP_MANAGER"],
  microapps: [
    {
      source: "XOOS",
      microappKey: "approval-decision",
      permissions: ["APPROVE", "READ"]
    }
  ]
};

describe("effective authorization helpers", () => {
  it("finds an authorized Microapp by source and key", () => {
    expect(
      findAuthorizedMicroapp(authorization, "approval-decision", "XOOS")
    ).toEqual(authorization.microapps[0]);
  });

  it("checks actions case-insensitively", () => {
    expect(
      hasMicroappPermission(
        authorization,
        "approval-decision",
        "approve",
        "XOOS"
      )
    ).toBe(true);
  });

  it("denies actions that are not granted", () => {
    expect(
      hasMicroappPermission(
        authorization,
        "approval-decision",
        "DELETE",
        "XOOS"
      )
    ).toBe(false);
  });
});
