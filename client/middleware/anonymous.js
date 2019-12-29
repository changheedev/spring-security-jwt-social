export default function({ store, redirect }) {
  if (store.state.loggedName) {
    return redirect("/");
  }
}
