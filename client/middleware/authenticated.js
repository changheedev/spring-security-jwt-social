export default function({ store, redirect, route }) {
  if (!store.state.loggedName)
    return redirect(`/login?redirect_uri=${route.path}`);
}
