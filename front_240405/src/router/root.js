import { Suspense, lazy } from "react";
import { createBrowserRouter } from "react-router-dom";
import productRouter from "./productRouter";
import noticeBoardRouter from "./noticeBoardRouter";
import userRouter from "./userRouter";
import { CheckoutPage } from "../pages/payments/CheckoutPage";
import { SuccessPage } from "../pages/payments/SuccessPage";
import { FailPage } from "../pages/payments/FailPage";
import "../styles/pages/paymentPage.scss";
import { PaymentSuccessPage } from "../pages/payments/PaymentSuccessPage";

const Loading = <div>Loading....</div>;
const Main = lazy(() => import("../pages/MainPage"));
const CampPage = lazy(() => import("../pages/camp/CampPage"));
const ProductIndex = lazy(() => import("../pages/product/IndexPage_p"));
const NoticeBoardIndex = lazy(() => import("../pages/noticeboard/IndexPage_n"));
const LoginIndex = lazy(() => import("../pages/user/IndexPage_u"));
const CampingImage = lazy(() => import("../pages/image/ImagePage_i"));

const root = createBrowserRouter([
  {
    path: "/",
    element: (
      <Suspense fallback={Loading}>
        <Main />
      </Suspense>
    ),
  },
  {
    path: "/:prediction",
    element: (
      <Suspense fallback={Loading}>
        <CampingImage />
      </Suspense>
    ),
  },
  {
    path: "/camping",
    element: (
      <Suspense fallback={Loading}>
        <CampPage />
      </Suspense>
    ),
  },
  {
    path: "/product",
    element: (
      <Suspense fallback={Loading}>
        <ProductIndex />
      </Suspense>
    ),
    children: productRouter(),
  },
  {
    path: "/noticeboard",
    element: (
      <Suspense fallback={Loading}>
        <NoticeBoardIndex />
      </Suspense>
    ),
    children: noticeBoardRouter(),
  },
  {
    path: "/user",
    element: (
      <Suspense fallback={Loading}>
        <LoginIndex />
      </Suspense>
    ),
    children: userRouter(),
  },
  {
    path: "/payment",
    element: <CheckoutPage />,
  },
  {
    path: "/payment/success",
    element: <SuccessPage />,
  },
  {
    path: "/payment/fail",
    element: <FailPage />,
  },
  {
    path: "/payment/success/1",
    element: <PaymentSuccessPage />,
  },
]);

export default root;
