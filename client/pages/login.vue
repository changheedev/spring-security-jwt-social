<template>
  <div class="container-login">
    <H1 class="login-title">Spring Social</H1>
    <div class="container-login-social">
      <b-button
        v-for="item in social"
        :key="'button-' + item.provider"
        :id="'button-' + item.provider"
        :style="{ background: `url(${item.image}) no-repeat` }"
        @click.prevent="handleSocialLogin(item)"
      ></b-button>
    </div>
    <div class="or-separator">
      <div class="or-text">OR</div>
    </div>
    <div class="container-login-default">
      <b-form @submit.prevent="handleSubmit()">
        <b-form-group>
          <b-form-input
            id="input-username"
            type="text"
            v-model="authenticationRequest.username"
            placeholder="Email"
            trim
            required
          ></b-form-input>
        </b-form-group>
        <b-form-group>
          <b-form-input
            id="input-password"
            type="password"
            v-model="authenticationRequest.password"
            placeholder="Password"
            trim
            required
          ></b-form-input>
        </b-form-group>
        <b-button type="submit" variant="primary" block>Login</b-button>
      </b-form>
      <div class="container-signup-link">
        새로 오셨나요?
        <b-link href="/signup">회원가입하기</b-link>
      </div>
    </div>
  </div>
</template>

<script>
import { GOOGLE_AUTH_URL, NAVER_AUTH_URL, KAKAO_AUTH_URL } from "~/constants";

export default {
  asyncData({ query }) {
    let redirectUri = "http://localhost:3000";

    if (query.redirect_uri) redirectUri = redirectUri + query.redirect_uri;

    return {
      redirectUri: redirectUri
    };
  },
  middleware: ["anonymous"],
  data() {
    return {
      social: [
        {
          provider: "google",
          authUrl: GOOGLE_AUTH_URL,
          image: "/social/google.png"
        },
        {
          provider: "naver",
          authUrl: NAVER_AUTH_URL,
          image: "/social/naver.png"
        },
        {
          provider: "kakao",
          authUrl: KAKAO_AUTH_URL,
          image: "/social/kakao.png"
        }
      ],
      authenticationRequest: {
        username: "",
        password: ""
      }
    };
  },
  methods: {
    handleSubmit() {
      this.$axios
        .$post("/api/authorize", this.authenticationRequest)
        .then(response => {
          this.$router.push(this.redirectUri);
        });
    },
    handleSocialLogin(value) {
      window.location = `${value.authUrl}?redirect_uri=${this.redirectUri}`;
    }
  }
};
</script>

<style lang="scss" scoped>
.container-login {
  max-width: 400px;
  margin: 3rem auto;
  padding: 50px;
  border-radius: 0.25rem;
  box-shadow: 0 1px 11px rgba(0, 0, 0, 0.27);
  text-align: center;

  h1 {
    font-size: 2rem;
    margin-bottom: 2rem;
  }
}

.container-login-social {
  button {
    display: block;
    width: 300px;
    height: 50px;
    border: none;
    background-color: #fff;
  }
  button + button {
    margin-top: 8px;
  }
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

.container-login-default {
  button {
    height: 50px;
  }
}

.container-signup-link {
  margin-top: 2rem;
}
</style>
