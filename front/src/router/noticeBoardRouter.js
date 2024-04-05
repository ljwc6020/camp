import React, { Suspense, lazy } from "react";
import { Navigate } from "react-router-dom";

const Loading = <div>Loading...</div>;
const NoticeBoardList = lazy(() => import("../pages/noticeboard/ListPage_n"));
const NoticeBoardRead = lazy(() => import("../pages/noticeboard/ReadPage_n"));
const NoticeBoardAdd = lazy(() => import("../pages/noticeboard/AddPage_n"));
const NoticeBoardModify = lazy(() =>
  import("../pages/noticeboard/ModifyPage_n")
);

const noticeBoardRouter = () => {
  return [
    {
      path: "list",
      element: (
        <Suspense fallback={Loading}>
          <NoticeBoardList />
        </Suspense>
      ),
    },
    {
      path: "read/:nbno",
      element: (
        <Suspense fallback={Loading}>
          <NoticeBoardRead />
        </Suspense>
      ),
    },
    {
      path: "add",
      element: (
        <Suspense fallback={Loading}>
          <NoticeBoardAdd />
        </Suspense>
      ),
    },
    {
      path: "modify/:nbno",
      element: (
        <Suspense fallback={Loading}>
          <NoticeBoardModify />
        </Suspense>
      ),
    },
    { path: "", element: <Navigate replace to="list" /> },
  ];
};

export default noticeBoardRouter;
