export default function({ app }) {
  app.$axios.onRequest(config => {
    if (!config.method.toUpperCase().match(/^(GET|HEAD|TRACE|OPTIONS)$/)) {
      let csrfToken = app.$cookies.get("CSRF-TOKEN");
      config.headers.common["X-CSRF-TOKEN"] = csrfToken;
    }
  });
}
