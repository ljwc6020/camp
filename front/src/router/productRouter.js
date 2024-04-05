import React, { Suspense, lazy } from "react";
import { Navigate } from "react-router-dom";

const Loading = <div>Loading...</div>;
const ProductList = lazy(() => import("../pages/product/ListPage_p"));
const ProductRead = lazy(() => import("../pages/product/ReadPage_p"));
const ProductAdd = lazy(() => import("../pages/product/AddPage_p"));
const ProductModify = lazy(() => import("../pages/product/ModifyPage_p"));
const ProductCart = lazy(() => import("../pages/product/cart/CartPage_p"));

const productRouter = () => {
  return [
    {
      path: "list",
      element: (
        <Suspense fallback={Loading}>
          <ProductList />
        </Suspense>
      ),
    },
    {
      path: "read/:pno",
      element: (
        <Suspense fallback={Loading}>
          <ProductRead />
        </Suspense>
      ),
    },
    {
      path: "add",
      element: (
        <Suspense fallback={Loading}>
          <ProductAdd />
        </Suspense>
      ),
    },
    {
      path: "modify/:pno",
      element: (
        <Suspense fallback={Loading}>
          <ProductModify />
        </Suspense>
      ),
    },
    {
      path: "cart",
      element: (
        <Suspense fallback={Loading}>
          <ProductCart />
        </Suspense>
      ),
    },
    { path: "", element: <Navigate replace to="list/?page=1&size=12" /> },
    { path: "list", element: <Navigate replace to="list/?page=1&size=12" /> },
  ];
};

export default productRouter;
