import jwtAxios from "../util/jwtUtil";
import { API_SERVER_HOST } from "./userApi";

const host = `${API_SERVER_HOST}/noticeboard`;

export const getList = async (pageParam) => {
  const { page, size } = pageParam;

  const res = await jwtAxios.get(`${host}/list`, {
    params: { page: page, size: size },
  });

  return res.data;
};

export const getOne = async (nbno) => {
  const res = await jwtAxios.get(`${host}/${nbno}`);

  return res.data;
};

export const postOne = async (noticeboard) => {
  const res = await jwtAxios.post(`${host}/`, noticeboard);

  return res.data;
};

export const putOne = async (noticeboard) => {
  const res = await jwtAxios.put(`${host}/${noticeboard.nbno}`, noticeboard);

  return res.data;
};

export const deleteOne = async (noticeboard) => {
  const res = await jwtAxios.delete(`${host}/${noticeboard.nbno}`, {
    data: noticeboard, // 요청 본문에 noticeboard 객체를 포함시킵니다.
  });
  return res.data;
};
