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

  env: {
    baseUrl: process.env.BASE_URL || "http://localhost:3000",
    apis: {
      baseUrl: process.env.API_BASE_URL || "http://localhost:8080",
      auth: {
        login: {
          uri: "/api/authorize",
          method: "post"
        },
        logout: {
          uri: "/api/logout",
          method: "post"
        },
        social: {
          list: {
            google: {
              provider: "google",
              name: "구글",
              authUrl:
                process.env.API_BASE_URL ||
                "http://localhost:8080" + "/api/oauth2/authorize/google"
            },
            naver: {
              provider: "naver",
              name: "네이버",
              authUrl:
                process.env.API_BASE_URL ||
                "http://localhost:8080" + "/api/oauth2/authorize/naver"
            },
            kakao: {
              provider: "kakao",
              name: "카카오",
              authUrl:
                process.env.API_BASE_URL ||
                "http://localhost:8080" + "/api/oauth2/authorize/kakao"
            }
          },
          unlink: {
            uri: "/api/oauth2/unlink",
            method: "post"
          }
        }
      },
      users: {
        signup: {
          uri: "/api/users",
          method: "post"
        },
        getProfile: {
          uri: "/api/users/me",
          method: "get"
        },
        updateProfile: {
          uri: "/api/users/me",
          method: "put"
        },
        withdraw: {
          uri: "/api/users/withdraw",
          method: "delete"
        }
      }
    }
  },
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
    ["cookie-universal-nuxt", { alias: "cookiz" }],
    "@nuxtjs/moment"
  ],
  axios: {
    baseURL: process.env.API_BASE_URL || "http://localhost:8080",
    credentials: true
  },
  moment: {
    timezone: true
  }
};
