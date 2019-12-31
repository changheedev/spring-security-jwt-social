<template>
  <b-navbar type="light" variant="light" fixed="top">
    <b-navbar-brand href="/">Spring Social</b-navbar-brand>
    <b-navbar-nav class="ml-auto">
      <b-nav-item-dropdown
        id="my-nav-dropdown"
        :text="loggedName"
        toggle-class="nav-link-custom"
        right
        v-if="loggedName"
      >
        <b-dropdown-item to="/mypage">마이페이지</b-dropdown-item>
        <b-dropdown-item @click="logout()">로그아웃</b-dropdown-item>
      </b-nav-item-dropdown>
      <b-nav-item :to="`/login?redirect_uri=${$route.path}`" right v-else
        >로그인</b-nav-item
      >
    </b-navbar-nav>
  </b-navbar>
</template>

<script>
import { mapGetters } from "vuex";
export default {
  computed: mapGetters({
    loggedName: "loggedName"
  }),
  methods: {
    logout() {
      this.$axios.post("/api/authorize/logout").then(() => {
        this.$store.commit("clearLoggedName");
        this.$router.push("/login");
      });
    }
  }
};
</script>

<style lang="scss" scoped></style>
