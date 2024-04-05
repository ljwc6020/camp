import { useState } from "react";
import {
  createSearchParams,
  useNavigate,
  useSearchParams,
} from "react-router-dom";

const getNum = (param, defaultValue) => {
  if (!param) {
    return defaultValue;
  }
  return parseInt(param);
};

const useCustomMovePage = (pno) => {
  const navigate = useNavigate();
  const [refresh, setRefresh] = useState(false);
  const [queryParams] = useSearchParams();

  const page = getNum(queryParams.get("page"), 1);
  const size = getNum(queryParams.get("size"), 10);
  const reviewQnaPage = getNum(queryParams.get("reviewQnaPage"), 1);
  const reviewQnaSize = getNum(queryParams.get("reviewQnaSize"), 10);

  const queryDefault = createSearchParams({ page, size }).toString();

  const moveListPage = (pageParam) => {
    let queryString = "";

    if (pageParam) {
      const pageNum = getNum(pageParam.page, 1);
      const sizeNum = getNum(pageParam.size, 10);

      queryString = createSearchParams({
        page: pageNum,
        size: sizeNum,
      }).toString();
    } else {
      queryString = queryDefault;
    }

    navigate({
      pathname: `../list`,
      search: queryString,
    });
    setRefresh(!refresh);
  };

  const moveReadPage = (num) => {
    console.log(queryDefault);

    navigate({
      pathname: `../read/${num}`,
      search: queryDefault,
    });
  };

  const moveModifyPage = (num) => {
    console.log(queryDefault);

    navigate({
      pathname: `../modify/${num}`,
      search: queryDefault,
    });
  };

  const moveReviewQnaListPage = (pageParam) => {
    let queryString = "";

    if (pageParam) {
      const pageNum = getNum(pageParam.reviewQnaPage, 1);
      const sizeNum = getNum(pageParam.reviewQnaSize, 10);

      queryString = createSearchParams({
        reviewQnaPage: pageNum,
        reviewQnaSize: sizeNum,
      }).toString();
    } else {
      queryString = createSearchParams({
        reviewQnaPage: reviewQnaPage,
        reviewQnaSize: reviewQnaSize,
      }).toString();
    }

    navigate({
      pathname: `../read/${pno}`,
      search: queryString,
    });
    setRefresh(!refresh);
  };

  const moveProoductListPage = (pageParam) => {
    let queryString = "";

    if (pageParam) {
      const pageNum = getNum(pageParam.page, 1);
      const sizeNum = getNum(pageParam.size, 12);

      queryString = createSearchParams({
        page: pageNum,
        size: sizeNum,
      }).toString();
    } else {
      queryString = queryDefault;
    }

    navigate({
      pathname: `../list`,
      search: queryString,
    });
    setRefresh(!refresh);
  };

  return {
    moveModifyPage,
    moveReadPage,
    moveListPage,
    moveProoductListPage,
    moveReviewQnaListPage,
    page,
    size,
    reviewQnaPage,
    reviewQnaSize,
    refresh,
  };
};

export default useCustomMovePage;
