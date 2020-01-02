<template>
  <div class="container-mypage">
    <H1>마이 페이지</H1>

    <div class="area-profile">
      <h2>내 정보 관리</h2>
      <b-row no-gutters>
        <b-col cols="3" no-gutters>이름</b-col>
        <b-col cols="9" no-gutters>{{ profile.name }}</b-col>
      </b-row>
      <b-row no-gutters>
        <b-col cols="3" no-gutters>이메일</b-col>
        <b-col cols="9" no-gutters>{{ profile.email }}</b-col>
      </b-row>
    </div>

    <div class="area-manage-social">
      <h2>소셜 로그인 관리</h2>
      <b-row v-for="item in social" :key="`social_${item.provider}`" no-gutters>
        <b-col cols="3" class="social-name" no-gutters>{{ item.name }}</b-col>
        <b-col cols="9" v-if="linkedSocialAccount[item.provider]" no-gutters>
          <b-button size="sm" variant="outline-secondary" @click="unlinkSocialAccount(item)">연동해제</b-button>
          <span class="pl-2">
            {{
            linkedSocialAccount[item.provider] + " 연동완료"
            }}
          </span>
        </b-col>
        <b-col cols="9" v-else>
          <b-button size="sm" @click="linkSocialAccount(item)" no-gutters>연동하기</b-button>
        </b-col>
      </b-row>
    </div>
  </div>
</template>

<script>
import { GOOGLE_AUTH_URL, NAVER_AUTH_URL, KAKAO_AUTH_URL } from "~/constants";

export default {
  middleware: ["authenticated"],
  async asyncData({ app, route }) {
    const profileResponse = await app.$axios.get("/api/users/me");
    const socialAccountResponse = await app.$axios.get("/api/users/social");
    return {
      profile: profileResponse.data,
      linkedSocialAccount: socialAccountResponse.data,
      redirectUri: process.env.baseUrl + route.path
    };
  },
  data() {
    return {
      social: [
        {
          provider: "google",
          name: "구글",
          authUrl: GOOGLE_AUTH_URL
        },
        {
          provider: "naver",
          name: "네이버",
          authUrl: NAVER_AUTH_URL
        },
        {
          provider: "kakao",
          name: "카카오",
          authUrl: KAKAO_AUTH_URL
        }
      ]
    };
  },
  methods: {
    linkSocialAccount(value) {
      window.location = `${value.authUrl}?redirect_uri=${this.redirectUri}&callback=link`;
    },
    unlinkSocialAccount(value) {
      window.location = `${value.authUrl}?redirect_uri=${this.redirectUri}&callback=unlink`;
    }
  }
};
</script>

<style lang="scss" scoped>
.container-mypage {
  max-width: 700px;
  margin: 3rem auto;
  padding: 50px;
  border-radius: 0.25rem;
  box-shadow: 0 1px 11px rgba(0, 0, 0, 0.27);
}
.area-profile {
  margin-bottom: 3rem;
}
</style>
