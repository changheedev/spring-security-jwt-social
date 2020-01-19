<template>
  <section class="container">
    <div>
      <app-logo />
      <h2 class="title mt-5">JWT를 이용한 Spring Boot 인증 서버 Demo</h2>
      <div class="links">
        <a
          href="https://github.com/changhee-choi/spring-security-jwt-social"
          target="_blank"
          class="button--grey"
          >GitHub</a
        >
      </div>
    </div>
  </section>
</template>

<script>
import AppLogo from "~/components/AppLogo.vue";

export default {
  components: {
    AppLogo
  }
};
</script>

<style>
.container {
  min-height: 100vh;
  display: flex;
  justify-content: center;
  align-items: center;
  text-align: center;
}

.title {
  color: #526488;
  word-spacing: 5px;
  padding-bottom: 15px;
}

.links {
  padding-top: 15px;
}
</style>
