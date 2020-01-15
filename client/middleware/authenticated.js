export default function({ store, redirect, route }) {
  if (Object.entries(store.state.user).length === 0)
    return redirect(`/login?redirect_uri=${route.path}`);
}
