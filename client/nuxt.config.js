module.exports = {
  /*
   ** Headers of the page
   */
  head: {
    title: "client",
    meta: [
      { charset: "utf-8" },
      { name: "viewport", content: "width=device-width, initial-scale=1" },
      {
        hid: "description",
        name: "description",
        content: "spring-security-jwt-oauth2 client"
      }
    ],
    link: [{ rel: "icon", type: "image/x-icon", href: "/favicon.ico" }]
  },
  /*
   ** Customize the progress bar color
   */
  loading: { color: "#3B8070" },
  /*
   ** Style CSS
   */
  css: ["~/assets/style.css"],

  /*
   ** Build configuration
   */
  build: {
    /*
     ** Run ESLint on save
     */
    extend(config, { isDev, isClient }) {
      if (isDev && isClient) {
        config.module.rules.push({
          enforce: "pre",
          test: /\.(js|vue)$/,
          loader: "eslint-loader",
          exclude: /(node_modules)/
        });
      }
    }
  },

  modules: [
    "bootstrap-vue/nuxt",
    "@nuxtjs/axios",
    "cookie-universal-nuxt",
    // With options
    ["cookie-universal-nuxt", { alias: "cookiz" }]
  ],
  axios: {
    proxy: true
  },
  proxy: {
    "/api/": "http://localhost:8080"
  }
};
