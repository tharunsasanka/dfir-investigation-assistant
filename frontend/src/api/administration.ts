import type { User } from '../types/auth'
import type {
  CreateUserRequest,
  MessageResponse,
  PasswordChangeRequest,
  PermissionListParams,
  PermissionListResponse,
  ProfileUpdateRequest,
  RoleListParams,
  RoleListResponse,
  UpdateUserRequest,
  UserListParams,
  UserListResponse,
  UserUnlockResponse,
} from '../types/administration'
import { apiClient } from './client'

export async function getUsers(
  params: UserListParams = {},
): Promise<UserListResponse> {
  const response =
    await apiClient.get<UserListResponse>(
      '/users',
      {
        params,
      },
    )

  return response.data
}

export async function createUser(
  request: CreateUserRequest,
): Promise<User> {
  const response =
    await apiClient.post<User>(
      '/users',
      request,
    )

  return response.data
}

export async function getUser(
  userId: string,
): Promise<User> {
  const response =
    await apiClient.get<User>(
      `/users/${encodeURIComponent(userId)}`,
    )

  return response.data
}

export async function updateUser(
  userId: string,
  request: UpdateUserRequest,
): Promise<User> {
  const response =
    await apiClient.patch<User>(
      `/users/${encodeURIComponent(userId)}`,
      request,
    )

  return response.data
}

export async function unlockUser(
  userId: string,
): Promise<UserUnlockResponse> {
  const response =
    await apiClient.post<UserUnlockResponse>(
      `/users/${encodeURIComponent(userId)}/unlock`,
    )

  return response.data
}

export async function getRoles(
  params: RoleListParams = {},
): Promise<RoleListResponse> {
  const response =
    await apiClient.get<RoleListResponse>(
      '/roles',
      {
        params,
      },
    )

  return response.data
}

export async function getPermissions(
  params: PermissionListParams = {},
): Promise<PermissionListResponse> {
  const response =
    await apiClient.get<PermissionListResponse>(
      '/permissions',
      {
        params,
      },
    )

  return response.data
}

export async function updateProfile(
  request: ProfileUpdateRequest,
): Promise<User> {
  const response =
    await apiClient.patch<User>(
      '/profile',
      request,
    )

  return response.data
}

export async function changePassword(
  request: PasswordChangeRequest,
): Promise<MessageResponse> {
  const response =
    await apiClient.post<MessageResponse>(
      '/profile/password',
      request,
    )

  return response.data
}