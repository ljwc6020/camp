import React from "react";

const AlertModal = ({ title, content, callbackFn }) => {
  return (
    <div className="fixed top-0 left-0 z-[1055] flex h-full w-full justify-center items-center bg-black bg-opacity-50">
      <div className="bg-black bg-opacity-50 w-1/4 rounded mt-10 mb-10 px-6 min-w-[400px]">
        <div className="text-white py-6 text-center text-2xl border-b-4 border-white-500">
          {title}
        </div>
        <div className="p-6 text-center text-white py-6">{content}</div>
        <div className="flex justify-center">
          <button
            className="bg-yellow-500 text-white px-6 py-3 rounded mt-4 mb-4"
            onClick={() => {
              if (callbackFn) {
                callbackFn();
              }
            }}
          >
            확인
          </button>
        </div>
      </div>
    </div>
  );
};

export default AlertModal;
