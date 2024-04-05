import jwtAxios from "../util/jwtUtil";
import { API_SERVER_HOST } from "./userApi";

const host = `${API_SERVER_HOST}/reply`;

export const getBoardReply = async (nbno) => {
  const res = await jwtAxios.get(`${host}/list/${nbno}`);

  return res.data;
};

export const getReplyList = async (pageParam) => {
  const { nbno, page, size } = pageParam;

  const res = await jwtAxios.get(`${host}/list/${nbno}`, {
    params: { page: page, size: size },
  });

  return res.data;
};

export const postReply = async (replyObj) => {
  const res = await jwtAxios.post(`${host}/`, replyObj);

  return res.data;
};

export const getReply = async (nrno) => {
  const res = await jwtAxios.get(`${host}/${nrno}`);

  return res.data;
};

export const putReply = async (replyObj) => {
  const res = await jwtAxios.put(`${host}/${replyObj.nrno}`, replyObj);

  return res.data;
};

export const deleteReply = async (nrno) => {
  const res = await jwtAxios.delete(`${host}/${nrno}`);

  return res.data;
};
