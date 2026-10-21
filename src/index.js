export default {
  async fetch(request, env) {
    const config = {
      baseUrl: env.ACUMATICA_BASE_URL,
      username: env.ACUMATICA_USERNAME,
      password: env.ACUMATICA_PASSWORD,
      tenant: env.ACUMATICA_TENANT
    };

    // Temporary configuration check only.
    // Never return credentials in an HTTP response.
    const configured =
      Boolean(config.baseUrl) &&
      Boolean(config.username) &&
      Boolean(config.password) &&
      Boolean(config.tenant);

    return Response.json({
      configured,
    });
  },
};
