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
    //CSRF 쿠키가 없으면 서버에 CSRF 토큰을 요청하고 쿠키를 생성
    if (!app.$cookies.get("CSRF-TOKEN")) {
      const csrfToken = await app.$axios.$get(process.env.apis.auth.csrf.uri);
      app.$cookies.set("CSRF-TOKEN", csrfToken["CSRF-TOKEN"], {
        path: "/",
        maxAge: 60 * 60 * 24
      });
    }

    try {
      //프로필 정보를 불러온다
      const resUserInfo = await app.$axios({
        method: process.env.apis.users.getProfile.method,
        url: process.env.apis.users.getProfile.uri
      });
      const userInfo = resUserInfo.data;
      commit("setUser", userInfo);
      console.log(userInfo);
    } catch (err) {
      //토큰이 유효하지 않다면 토큰 쿠키를 삭제
      this.$cookies.remove("access_token");
    }
  }
};
