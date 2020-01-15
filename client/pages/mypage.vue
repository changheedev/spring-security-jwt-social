<template>
  <div class="container-mypage">
    <h1>마이페이지</h1>
    <b-container class="area-profile p-3 mb-5 shadow-sm rounded" fluid>
      <h2>프로필</h2>
      <b-row no-gutters>
        <b-col cols="3">이름</b-col>
        <b-col cols="9" v-if="editableProfile">
          <b-form-group>
            <b-form-input
              id="input-name"
              type="text"
              placeholder="이름"
              :value="newProfile.name.value"
              :state="newProfile.name.state"
              @input="value => updateNameVal(value)"
            ></b-form-input>
            <b-form-invalid-feedback id="input-name-feedback">{{
              newProfile.name.feedback
            }}</b-form-invalid-feedback>
          </b-form-group>
        </b-col>
        <b-col cols="9" v-else>{{ profile.name }}</b-col>
      </b-row>
      <b-row no-gutters>
        <b-col cols="3">이메일</b-col>
        <b-col cols="9" v-if="editableProfile">
          <b-form-group>
            <b-form-input
              id="input-email"
              type="text"
              placeholder="이메일"
              :value="newProfile.email.value"
              :state="newProfile.email.state"
              @input="value => updateEmailVal(value)"
            ></b-form-input>
            <b-form-invalid-feedback id="input-email-feedback">{{
              newProfile.email.feedback
            }}</b-form-invalid-feedback>
          </b-form-group>
        </b-col>
        <b-col cols="9" v-else>{{ profile.email }}</b-col>
      </b-row>
      <b-row v-if="!editableProfile" no-gutters>
        <b-col cols="3">등급</b-col>
        <b-col cols="9">{{ authorityName }}</b-col>
      </b-row>
      <b-row align-h="end" v-if="editableProfile" no-gutters>
        <b-button @click="updateProfile()">저장</b-button>
        <b-button
          class="ml-3"
          variant="outline-secondary"
          @click="toggleEditProfile()"
          >취소</b-button
        >
      </b-row>
      <b-row align-h="end" v-else no-gutters>
        <b-button @click="toggleEditProfile()">프로필 변경</b-button>
      </b-row>
    </b-container>

    <div class="area-manage-social p-3 mb-5 shadow-sm rounded">
      <h2>소셜 로그인 관리</h2>
      <div v-if="profile.socialProvider">
        <b-row no-gutters>
          <b-col cols="4" sm="3">제공자</b-col>
          <b-col cols="8" sm="9">
            {{ social[profile.socialProvider].name }}
          </b-col>
        </b-row>
        <b-row no-gutters>
          <b-col cols="4" sm="3">연동 일자</b-col>
          <b-col cols="8" sm="9">
            {{ transDateTime }}
          </b-col>
        </b-row>
        <b-row align-h="end" no-gutters>
          <b-button @click="unlinkSocialAccount()">연동해제</b-button>
        </b-row>
      </div>
      <b-row
        v-for="item in social"
        :key="`social_${item.provider}`"
        no-gutters
        v-else
      >
        <b-col cols="3" class="social-name">{{ item.name }}</b-col>
        <b-col cols="9">
          <b-button size="sm" @click="linkSocialAccount(item)"
            >연동하기</b-button
          >
        </b-col>
      </b-row>
    </div>
    <div class="area-manage-social shadow-sm rounded p-3">
      <h2>회원 탈퇴</h2>
      <b-row align-h="end" no-gutters>
        <b-col cols="12">
          <p>회원 탈퇴시 모든 정보가 삭제됩니다.</p>
        </b-col>
        <b-button variant="outline-danger" @click="withdraw()"
          >회원탈퇴</b-button
        >
      </b-row>
    </div>
  </div>
</template>

<script>
import { GOOGLE_AUTH_URL, NAVER_AUTH_URL, KAKAO_AUTH_URL } from "~/constants";
export default {
  middleware: ["authenticated"],
  async asyncData({ app, store, route }) {
    return {
      profile: store.getters.user,
      isAdmin: store.getters.isAdmin,
      redirectUri: process.env.baseUrl + route.path
    };
  },
  data() {
    return {
      social: {
        google: {
          provider: "google",
          name: "구글",
          authUrl: GOOGLE_AUTH_URL
        },
        naver: {
          provider: "naver",
          name: "네이버",
          authUrl: NAVER_AUTH_URL
        },
        kakao: {
          provider: "kakao",
          name: "카카오",
          authUrl: KAKAO_AUTH_URL
        }
      },
      editableProfile: false,
      newProfile: {
        name: {
          value: "",
          state: null,
          feedback: ""
        },
        email: {
          value: "",
          state: null,
          feedback: ""
        }
      }
    };
  },
  computed: {
    authorityName() {
      if (this.isAdmin) return "관리자";
      return "일반멤버";
    },
    transDateTime() {
      return this.$moment(this.profile.linkedAt)
        .tz("Asia/Seoul")
        .format("YYYY.MM.DD HH:mm:ss");
    }
  },
  methods: {
    copyProfile() {
      this.newProfile.name = {
        value: this.profile.name,
        state: null,
        feedback: ""
      };
      this.newProfile.email = {
        value: this.profile.email,
        state: null,
        feedback: ""
      };
    },
    updateNameVal(value) {
      this.newProfile.name.value = value;
      this.newProfile.name.state = null;
      this.newProfile.name.feedback = "";
    },
    updateEmailVal(value) {
      this.newProfile.email.value = value;
      this.newProfile.email.state = null;
      this.newProfile.email.feedback = "";
    },
    linkSocialAccount(value) {
      window.location = `${value.authUrl}?redirect_uri=${this.redirectUri}&callback=link`;
    },
    unlinkSocialAccount() {
      this.$axios
        .post("/api/oauth2/unlink")
        .then(res => {
          alert("연동 해제 되었습니다.");
          location.reload();
        })
        .catch(err => {
          alert(err.response.data.message);
        });
    },
    toggleEditProfile() {
      if (this.editableProfile) this.editableProfile = false;
      else {
        this.copyProfile();
        this.editableProfile = true;
      }
    },
    updateProfile() {
      this.$axios
        .put("/api/users/me", {
          name: this.newProfile.name.value,
          email: this.newProfile.email.value
        })
        .then(res => {
          alert("프로필이 변경되었습니다.");
          location.reload();
        })
        .catch(err => {
          if (err.response.data.errors.length > 0) {
            console.log(err.response);
            err.response.data.errors.forEach(error => {
              this.newProfile[error.field].state = false;
              this.newProfile[error.field].feedback = error.defaultMessage;
            });

            console.log(this.newProfile);
          } else alert("프로필을 업데이트 하는 과정에서 오류가 발생했습니다.");
        });
    },
    withdraw() {
      const withdrawConfirm = confirm("회원탈퇴를 진행하시겠습니까?");
      if (!withdrawConfirm) return;
      this.$axios
        .delete("/api/users/withdraw")
        .then(res => (window.location = "/"))
        .catch(err => {
          alert("회원탈퇴 과정에서 오류가 발생했습니다.");
        });
    }
  }
};
</script>

<style lang="scss" scoped>
.container-mypage {
  max-width: 700px;
  margin: 1rem auto;
  padding: 15px;
}
.area-profile {
  margin-bottom: 3rem;
}
</style>
