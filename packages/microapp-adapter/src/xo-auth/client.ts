import type { XOOSMicroappBridge } from "@xoos/contracts";
import type {
  XOApplicationsResponse,
  XOListOptions,
  XOOrganizationMembersResponse,
  XOOrganizationsResponse
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
    list: async (): Promise<XOOrganizationsResponse> =>
      this.bridge.services.request<XOOrganizationsResponse>(
        "xo-auth.organizations.list"
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
