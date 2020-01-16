<template>
  <div class="container-login">
    <social-login :redirectUri="redirectUri"></social-login>
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
import SocialLogin from "~/components/SocialLogin";
export default {
  layout: "non-header",
  components: { SocialLogin },
  asyncData({ query }) {
    let redirectUri = process.env.baseUrl;
    if (query.redirect_uri) redirectUri = redirectUri + query.redirect_uri;
    return {
      redirectUri: redirectUri
    };
  },
  middleware: ["anonymous"],
  data() {
    return {
      authenticationRequest: {
        username: "",
        password: ""
      }
    };
  },
  methods: {
    handleSubmit() {
      this.$axios({
        method: process.env.apis.auth.login.method,
        url: process.env.apis.auth.login.uri,
        data: this.authenticationRequest
      }).then(response => {
        window.location = this.redirectUri;
      });
    }
  }
};
</script>

<style lang="scss" scoped>
.container-login {
  max-width: 400px;
  margin: 0 auto;
  padding: 0 20px;

  @media (max-width: 400px) {
    padding: 20px;
  }
}

.container-social-button {
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
  text-align: center;
}
</style>
