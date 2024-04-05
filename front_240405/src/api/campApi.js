import jwtAxios from "../util/jwtUtil";
import { API_SERVER_HOST } from "./userApi";

const host = `${API_SERVER_HOST}/camping`;

export const getBasedList = async (pageNo) => {
  const res = await jwtAxios.get(`${host}/basedList?pageNo=${pageNo}`);
  return res.data;
};

export const getLocationList = async (pageNo, latitude, longitude) => {
  const res = await jwtAxios.get(
    `${host}/locationBasedList?pageNo=${pageNo}&mapX=${latitude}&mapY=${longitude}`
  );

  return res.data;
};
// 백단에서 searchList 를 불러오는 함수
export const getSearchList = async (pageNo, keyw) => {
  // 비동기로 받아오는대, get 방식으로
  const res = await jwtAxios.get(
    // 호출하는 주소            // 프론트에서, ${} 보통 이안에 변수가 들어가요
    `${host}/searchList?pageNo=${pageNo}&keyword=${keyw}`
  );

  return res.data;
};
