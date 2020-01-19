<template>
  <div class="container-signup">
    <social-login :redirectUri="redirectUris.afterSocialLogin"></social-login>
    <b-form @submit.prevent="handleSubmit()">
      <b-form-group>
        <b-form-input
          id="input-name"
          type="text"
          :state="signupRequest.name.state"
          :value="signupRequest.name.value"
          @input="value => updateValue('name', value)"
          placeholder="이름"
          trim
          required
        ></b-form-input>
        <b-form-invalid-feedback id="input-name-feedback">{{
          signupRequest.name.feedback
        }}</b-form-invalid-feedback>
      </b-form-group>
      <b-form-group>
        <b-form-input
          id="input-email"
          type="text"
          :state="signupRequest.email.state"
          :value="signupRequest.email.value"
          @input="value => updateValue('email', value)"
          placeholder="이메일"
          trim
          required
        ></b-form-input>
        <b-form-invalid-feedback id="input-email-feedback">{{
          signupRequest.email.feedback
        }}</b-form-invalid-feedback>
      </b-form-group>
      <b-form-group>
        <b-form-input
          id="input-password"
          type="password"
          :state="signupRequest.password.state"
          :value="signupRequest.password.value"
          @input="value => updateValue('password', value)"
          placeholder="비밀번호"
          trim
          required
        ></b-form-input>
        <b-form-invalid-feedback id="input-password-feedback">{{
          signupRequest.password.feedback
        }}</b-form-invalid-feedback>
      </b-form-group>
      <b-button type="submit" variant="primary" block>회원가입</b-button>
    </b-form>
    <div class="mt-3">이미 계정이 있으신가요? <a href="/login">로그인</a></div>
  </div>
</template>

<script>
import SocialLogin from "~/components/SocialLogin";
export default {
  layout: "non-header",
  middleware: ["anonymous"],
  components: { SocialLogin },
  data() {
    return {
      signupRequest: {
        name: {
          value: "",
          state: null,
          feedback: ""
        },
        email: {
          value: "",
          state: null,
          feedback: ""
        },
        password: {
          value: "",
          state: null,
          feedback: ""
        }
      },
      redirectUris: {
        afterSocialLogin: process.env.baseUrl,
        afterSignup: "/login"
      }
    };
  },
  methods: {
    updateValue(field, value) {
      this.signupRequest[field].value = value;
      this.signupRequest[field].state = null;
      this.signupRequest[field].feedback = "";
    },
    handleSubmit() {
      this.$axios({
        method: process.env.apis.users.signup.method,
        url: process.env.apis.users.signup.uri,
        data: {
          name: this.signupRequest.name.value,
          email: this.signupRequest.email.value,
          password: this.signupRequest.password.value
        }
      })
        .then(() => {
          alert("회원가입이 완료되었습니다.");
          this.$router.push(this.redirectUris.afterSignup);
        })
        .catch(err => {
          if (err.response.data.errors.length > 0) {
            err.response.data.errors.forEach(error => {
              this.signupRequest[error.field].state = false;
              this.signupRequest[error.field].feedback = error.defaultMessage;
            });
          } else alert("회원가입 과정에서 오류가 발생했습니다.");
        });
    }
  }
};
</script>

<style lang="scss" scoped>
.container-signup {
  max-width: 400px;
  margin: 0 auto;
  padding: 0 20px;

  button {
    height: 50px;
  }
}
</style>
