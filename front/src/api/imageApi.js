import { API_SERVER_HOST } from "./userApi";
import jwtAxios from "../util/jwtUtil";
import axios from "axios";

const host = `${API_SERVER_HOST}`;

export const getInform = async (prediction) => {
  const res = await axios.get(`${host}/${prediction}`);

  return res.data;
};
