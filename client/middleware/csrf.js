export default function({ app }) {
  if (process.server || app.$cookies.get("CSRF-TOKEN")) return;
  app.$axios.$get(process.env.apis.auth.csrf.uri);
}
