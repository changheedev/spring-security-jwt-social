export const state = () => {
  return {
    user: null,
    loggedName: null
  };
};

export const mutations = {
  setUser(state, user) {
    state.user = user;
  },
  clearUser(state) {
    state.user = null;
  },
  setLoggedName(state, loggedName) {
    state.loggedName = loggedName;
  },
  clearLoggedName(state) {
    state.loggedName = null;
  }
};

export const getters = {
  user(state) {
    return state.user;
  },
  loggedName(state) {
    return state.loggedName;
  }
};

export const actions = {
  nuxtServerInit({ commit }) {
    const loggedName = this.$cookies.get("logged_name");
    if (loggedName) {
      let decodedName = decodeURI(loggedName).replace("+", " ");
      commit("setLoggedName", decodedName);
    }
  }
};
