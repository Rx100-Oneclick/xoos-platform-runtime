export interface XOApplication {
  id: string;
  appKey: string;
  name: string;
  description: string | null;
  publisherName: string;
  companyWebsite: string | null;
  logoStoragePath: string | null;
  architecture: string;
  defaultEnvironment: string;
  status: string;
  launchUrl: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface XOOrganizationMember {
  memberId: string;
  userId: string | null;
  roleId: string;
  email: string;
  fullName: string;
  invitationStatus: string;
  status: string | null;
  setupComplete: boolean;
  assignedOn: string | null;
  avatarUrl: string | null;
  createdAt: string | null;
  updatedAt: string | null;
}

export interface XOPagination {
  limit: number;
  offset: number;
  total: number;
}

export interface XOApplicationsResponse {
  tenantId: string;
  applications: XOApplication[];
  pagination: XOPagination;
}

export interface XOOrganizationMembersResponse {
  tenantId: string;
  members: XOOrganizationMember[];
  pagination: XOPagination;
}

export interface XOListOptions {
  limit?: number;
  offset?: number;
}
