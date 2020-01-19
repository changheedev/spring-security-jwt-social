<template>
  <div class="container-social-button">
    <a href="/"><H1 class="text-center">Spring Social</H1></a>
    <b-button
      v-for="item in socials"
      :key="`button-${item.provider}`"
      :id="`button-${item.provider}`"
      :class="`button-${item.provider}`"
      @click.prevent="handleSocialLogin(item)"
      block
      >{{ item.name }} 아이디로 로그인</b-button
    >
    <div class="or-separator">
      <div class="or-text">또는</div>
    </div>
  </div>
</template>
<script>
export default {
  props: ["redirectUri"],
  data() {
    return {
      socials: process.env.apis.auth.social.list
    };
  },
  methods: {
    handleSocialLogin(value) {
      window.location = `${value.authUrl}?redirect_uri=${this.redirectUri}&callback=login`;
    }
  }
};
</script>
<style lang="scss" scoped>
a {
  color: #333;
}

button {
  margin: 0 auto;
  padding: 8px;
  height: 50px;
  border: none;
  font-size: 15px;
  background-size: 24px !important;
  background-repeat: no-repeat !important;
  background-position: 15px 12px !important;
}

button + button {
  margin-top: 8px;
}

.button-google {
  background: #fff;
  background-image: url("/social/google.png");
  color: rgba(0, 0, 0, 0.54);
  border-radius: 0.25rem;
  box-shadow: 0 1px 2px rgba(0, 0, 0, 0.27);
  font-family: "Roboto", sans-serif;
  font-weight: bold;
}
.button-naver {
  background: #1ec800;
  background-image: url("/social/naver.png");
  color: #fff;
  font-family: "Nanum Barun Gothic", sans-serif;
  font-weight: 700;
}
.button-kakao {
  background: #f4e016;
  background-image: url("/social/kakao.png");
  color: #2d1617;
  font-weight: 600;
}

.or-separator {
  border-bottom: 1px solid #eee;
  padding: 10px 0;
  position: relative;
  display: block;
  margin-top: 20px;
  margin-bottom: 30px;
  font-size: 1em;
}

.or-text {
  position: absolute;
  left: 46%;
  top: 0;
  background: #fff;
  padding: 10px;
  color: rgba(0, 0, 0, 0.45);
}
</style>
