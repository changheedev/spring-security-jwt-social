<template>
  <div class="container-signup">
    <H1>회원가입</H1>
    <b-form @submit.prevent="handleSubmit()">
      <b-form-group>
        <b-form-input
          id="input-name"
          type="text"
          v-model="signupRequest.name"
          placeholder="이름"
          required="required"
        ></b-form-input>
      </b-form-group>
      <b-form-group>
        <b-form-input
          id="input-email"
          type="text"
          v-model="signupRequest.email"
          placeholder="이메일"
          required="required"
        ></b-form-input>
      </b-form-group>
      <b-form-group>
        <b-form-input
          id="input-password"
          type="password"
          v-model="signupRequest.password"
          placeholder="비밀번호"
          required="required"
        ></b-form-input>
      </b-form-group>
      <b-button type="submit" variant="primary" block>회원가입</b-button>
    </b-form>
  </div>
</template>

<script>
export default {
  data() {
    return {
      signupRequest: {
        name: "",
        email: "",
        password: ""
      }
    };
  },
  methods: {
    handleSubmit() {
      this.$axios({
        method: process.env.apis.users.signup.method,
        url: process.env.apis.users.signup.uri,
        data: this.signupRequest
      })
        .then(() => {
          alert("회원가입이 완료되었습니다.");
          this.$router.push("/login");
        })
        .catch(() => {
          alert("회원가입 과정에서 오류가 발생했습니다.");
        });
    }
  }
};
</script>

<style lang="scss" scoped>
.container-signup {
  max-width: 400px;
  margin: 3rem auto;
  padding: 50px;
  border-radius: 0.25rem;
  box-shadow: 0 1px 11px rgba(0, 0, 0, 0.27);
  text-align: center;

  button {
    height: 50px;
  }
}
</style>
