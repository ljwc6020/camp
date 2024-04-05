import React from "react";

const LoadingModal = () => {
  return (
    <div
      className={`fixed top-0 left-0 z-[1055] flex h-full w-full  place-items-center justify-center bg-black bg-opacity-20`}
    >
      <div className=" rounded-3xl bg-white bg-opacity-85 min-w-min h-1/4  min-w-[600px] flex justify-center items-center ">
        <div className="text-4xl font-extrabold text-gray-400 m-20">
          로딩 중...
        </div>
      </div>
    </div>
  );
};

export default LoadingModal;
