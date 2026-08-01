import type { DataSource } from "./base";

export interface ApiResult<T> {
  data: T;
  source: DataSource;
  error?: string;
}
