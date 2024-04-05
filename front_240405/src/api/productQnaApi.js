import axios from "axios";
import jwtAxios from "../util/jwtUtil";
import { API_SERVER_HOST } from "./userApi";

const host = `${API_SERVER_HOST}/qna`;

export const getQnaList = async (pageParam, pno) => {
  const { page: reviewQnaPage, size: reviewQnaSize } = pageParam;

  const res = await axios.get(`${host}/list/${pno}`, {
    params: { page: reviewQnaPage, size: reviewQnaSize },
  });
  return res.data;
};

export const getQna = async (qno) => {
  const res = await axios.get(`${host}/read/${qno}`);
  return res.data;
};

export const postQna = async (qna, pno) => {
  const header = { headers: { "Content-Type": "application/json" } };

  const res = await jwtAxios.post(`${host}/`, qna, header);
  return res.data;
};

export const putQna = async (qno, qna) => {
  const header = { headers: { "Content-Type": "application/json" } };

  const res = await jwtAxios.put(`${host}/${qno}`, qna, header);
  return res.data;
};

export const deleteQna = async (qna) => {
  const res = await jwtAxios.delete(`${host}/${qna.qno}`, {
    data: qna, // 요청 본문에 noticeboard 객체를 포함시킵니다.
  });
  return res.data;
};
