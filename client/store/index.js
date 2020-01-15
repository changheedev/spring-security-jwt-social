export const state = () => {
  return {
    user: {}
  };
};

export const mutations = {
  setUser(state, user) {
    state.user = user;
  },
  clearUser(state) {
    state.user = {};
  }
};

export const getters = {
  user(state) {
    return state.user;
  },
  loggedName(state) {
    if (state.user.hasOwnProperty("name")) return state.user.name;
    return "";
  },
  isAdmin(state) {
    if (state.user.authorities && state.user.authorities.includes("ROLE_ADMIN"))
      return true;
    return false;
  }
};

export const actions = {
  async nuxtServerInit({ commit }, { app }) {
    try {
      //토큰으로 프로필 정보를 불러온다
      const resUserInfo = await app.$axios({
        method: process.env.apis.users.getProfile.method,
        url: process.env.apis.users.getProfile.uri
      });
      const userInfo = resUserInfo.data;
      commit("setUser", userInfo);
    } catch (err) {
      //토큰이 유효하지 않다면 쿠키를 삭제
      this.$cookies.remove("access_token");
    }
  }
};
