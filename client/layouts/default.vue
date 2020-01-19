<template>
  <div class="main-container">
    <header-navbar></header-navbar>
    <nuxt />
  </div>
</template>

<script>
import HeaderNavbar from "~/components/layout/HeaderNavbar";

export default {
  components: { HeaderNavbar }
};
</script>

<style lang="scss" scoped>
.main-container {
  min-height: 100vh;
  padding-top: 56px;
}
</style>
