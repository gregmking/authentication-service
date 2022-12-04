export class User {
  public u_id: string;
  public u_email: string;
  public u_password: string;
  public u_refresh_token: string;
  public u_role: string;
  public u_enabled: boolean;

  public map = <
    T extends {
      id: string;
      u_email: string;
      u_password: string;
      u_refresh_token: string;
      u_role: string;
      u_enabled: boolean;
    }
  >(
    recordset: T
  ) => {
    if (!recordset) {
      return;
    }

    this.u_id = recordset.id;
    this.u_email = recordset.u_email;
    this.u_password = recordset.u_password;
    this.u_refresh_token = recordset.u_refresh_token;
    this.u_role = recordset.u_role;
    this.u_enabled = recordset.u_enabled;
  };
}
