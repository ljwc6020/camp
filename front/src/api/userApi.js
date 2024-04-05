import axios from "axios";
import jwtAxios from "../util/jwtUtil";
export const API_SERVER_HOST = "http://localhost:8080";

const host = `${API_SERVER_HOST}/api/user`;

export const loginPost = async (loginParam) => {
  const header = { headers: { "Content-Type": "x-www-form-urlencoded" } };

  const form = new FormData();
  form.append("username", loginParam.email);
  form.append("password", loginParam.pw);

  const res = await axios.post(`${host}/login`, form, header);

  return res.data;
};

export const modifyUser = async (user) => {
  const res = await jwtAxios.put(`${host}/modify`, user);

  return res.data;
};

export const joinUser = async (user) => {
  const res = await axios.post(`${host}/join`, user);

  return res.data;
};

export const removeUser = async (email) => {
  const res = await jwtAxios.delete(`${host}/remove/${email}`, {});

  return res.data;
};

export const readUser = async (email) => {
  const res = await jwtAxios.get(`${host}/mypage/${email}`, {});

  return res.data;
};

export const sendEmail = async (email) => {
  const formData = new URLSearchParams();
  formData.append("email", email);
  const res = await axios.post(`${host}/reset-pw`, formData);
  return res.data;
};
