export enum AuditAction {
  REGISTER = 'REGISTER',
  LOGIN = 'LOGIN',
  LOGOUT = 'LOGOUT',
  PASSWORD_CHANGED = 'PASSWORD_CHANGED',
  TWO_FA_ENABLED = 'TWO_FA_ENABLED',
  FORGOT_PASSWORD = 'FORGOT_PASSWORD',
  RESET_PASSWORD = 'RESET_PASSWORD',
}

export enum AuditStatus {
  SUCCESS = 'success',
  FAILED = 'failed',
}
