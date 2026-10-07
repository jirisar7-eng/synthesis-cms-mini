import { defineConfig, env } from "prisma/config";

export default defineConfig({
  schema: "prisma/schema.prisma",
  datasource: {
    url: env("SYNTHESIS_SECRET_DATABASE_URL"),
  },
});
