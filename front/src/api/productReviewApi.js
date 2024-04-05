import axios from "axios";
import jwtAxios from "../util/jwtUtil";
import { API_SERVER_HOST } from "./userApi";

const host = `${API_SERVER_HOST}/review`;

export const getReviewList = async (pageParam, pno) => {
  const { page: reviewQnaPage, size: reviewQnaSize } = pageParam;

  const res = await axios.get(`${host}/list/${pno}`, {
    params: { page: reviewQnaPage, size: reviewQnaSize },
  });
  return res.data;
};

export const getReview = async (prno) => {
  const res = await axios.get(`${host}/read/${prno}`);
  return res.data;
};

export const postReview = async (review, pno) => {
  const header = { headers: { "Content-Type": "multipart/form-data" } };

  const res = await jwtAxios.post(`${host}/`, review, header);
  return res.data;
};

export const putReview = async (prno, review) => {
  const header = { headers: { "Content-Type": "multipart/form-data" } };

  const res = await jwtAxios.put(`${host}/${prno}`, review, header);
  return res.data;
};

export const deleteReview = async (review) => {
  const res = await jwtAxios.delete(`${host}/${review.prno}`, {
    data: review, // 요청 본문에 noticeboard 객체를 포함시킵니다.
  });
  return res.data;
};
