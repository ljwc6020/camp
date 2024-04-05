import axios from "axios";
import { getCookie, setCookie } from "./cookieUtil";
import { API_SERVER_HOST } from "../api/userApi";

const jwtAxios = axios.create();

const refreshJWT = async (accessToken, refreshToken) => {
  const host = API_SERVER_HOST;

  const header = { headers: { Authorization: `Bearer ${accessToken}` } };

  const res = await axios.get(
    `${host}/api/user/refresh?refreshToken=${refreshToken}`,
    header
  );

  console.log("----------------------");
  console.log(res.data);

  return res.data;
};

// 로그인 페이지로 리디렉션하는 함수
const redirectToLoginPage = () => {
  alert("로그인 해주세요!");
  window.location.href = "/user/login"; // 로그인 페이지 URL로 이동
};

// before request 요청이 전송되기 전에 실행되는 함수
const beforeReq = (config) => {
  console.log("before request.............");

  const userInfo = getCookie("user");

  if (!userInfo) {
    console.log("User NOT FOUND");
    redirectToLoginPage(); // 사용자를 로그인 페이지로 리디렉션
    return Promise.reject({ response: { data: { error: "REQUIRE_LOGIN" } } });
  }

  const { accessToken } = userInfo;

  // Authorization (허가)헤더 처리
  config.headers.Authorization = `Bearer ${accessToken}`;

  return config;
};

// fail request 요청에 오류가 있는 경우
const requestFail = (err) => {
  console.log("request error............");

  return Promise.reject(err);
};

// before return response 응답이 반환되기 전에
const beforeRes = async (res) => {
  console.log("before return response...........");

  console.log(res);

  //'ERROR_ACCESS_TOKEN'
  const data = res.data;

  if (data && data.error === "ERROR_ACCESS_TOKEN") {
    const userCookieValue = getCookie("user");

    const result = await refreshJWT(
      userCookieValue.accessToken,
      userCookieValue.refreshToken
    );
    console.log("refreshJWT RESULT", result);

    userCookieValue.accessToken = result.accessToken;
    userCookieValue.refreshToken = result.refreshToken;

    setCookie("user", JSON.stringify(userCookieValue), 1);
    // 원래의 호출
    // 갱신된 토큰들을 다시 저장하고 원래 원했던 호출을 다시 시도
    const originalRequest = res.config;

    originalRequest.headers.Authorization = `Bearer ${result.accessToken}`;

    return await axios(originalRequest);
  }

  return res;
};

// fail response 응답이 오류가 있는 경우
const responseFail = (err) => {
  console.log("response fail error.............");
  return Promise.reject(err);
};

jwtAxios.interceptors.request.use(beforeReq, requestFail);

jwtAxios.interceptors.response.use(beforeRes, responseFail);

export default jwtAxios;
