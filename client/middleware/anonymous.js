export default function({ store, redirect }) {
  if (!Object.entries(store.state.user).length === 0) {
    return redirect("/");
  }
}
