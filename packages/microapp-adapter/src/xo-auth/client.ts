import type { XOOSMicroappBridge } from "@xoos/contracts";
import type {
  XOApplicationsResponse,
  XOListOptions,
  XOOrganizationMembersResponse,
  XOOrganizationResponse
} from "./types";

export class XOAuthClient {
  constructor(private readonly bridge: XOOSMicroappBridge) {}

  readonly applications = {
    list: async (options: XOListOptions = {}): Promise<XOApplicationsResponse> =>
      this.bridge.services.request<XOApplicationsResponse>(
        "xo-auth.applications.list",
        options
      )
  };

  readonly organizations = {
    getCurrent: async (): Promise<XOOrganizationResponse> =>
      this.bridge.services.request<XOOrganizationResponse>(
        "xo-auth.organizations.get-current"
      )
  };

  readonly organizationMembers = {
    list: async (
      options: XOListOptions = {}
    ): Promise<XOOrganizationMembersResponse> =>
      this.bridge.services.request<XOOrganizationMembersResponse>(
        "xo-auth.organization-members.list",
        options
      )
  };
}
