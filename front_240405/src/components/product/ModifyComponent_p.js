import React, { useEffect, useRef, useState } from "react";
import useCustomMovePage from "../../hooks/useCustomMovePage";
import { deleteOne, getOne, putOne } from "../../api/productApi";
import LoadingModal from "../modal/LoadingModal";
import AlertModal from "../modal/AlertModal";
import { API_SERVER_HOST } from "../../api/userApi";
import "../../styles/components/modifyComponent.scss";

const initState = {
  pname: "",
  pdesc: "",
  price: 0,
  delFlag: false,
  uploadFileNames: [],
};

const host = API_SERVER_HOST;

const ModifyComponent_p = ({ pno }) => {
  const [product, setProduct] = useState({ ...initState });
  const [result, setResult] = useState(null);
  const { moveReadPage, moveProoductListPage } = useCustomMovePage();
  const [loading, setLoading] = useState(false);
  const uploadRef = useRef();
  const [imagePreviewUrl, setImagePreviewUrl] = useState("");
  const [formattedPrice, setFormattedPrice] = useState("");

  useEffect(() => {
    getOne(pno).then((data) => {
      setProduct(data);
      // 데이터 로딩 시 숫자 가격을 콤마 포맷으로 변환하여 상태에 저장
      setFormattedPrice(
        data.price.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",")
      );
    });
  }, [pno]);

  const handleChangeProduct = (e) => {
    let { name, value } = e.target;
    if (name === "price") {
      // 입력 값에서 숫자만 추출
      const numericValue = value.replace(/[^\d]/g, "");
      // 상태 업데이트
      setProduct({
        ...product,
        [name]: numericValue,
      });
      // 콤마 포맷으로 변환하여 별도의 상태에 저장
      setFormattedPrice(numericValue.replace(/\B(?=(\d{3})+(?!\d))/g, ","));
    } else {
      setProduct({
        ...product,
        [name]: value,
      });
    }
  };

  // // 이미지 등록 시 미리보기 생성
  const handleImageChange = (e) => {
    e.preventDefault();

    let reader = new FileReader();
    let file = e.target.files[0];

    reader.onloadend = () => {
      setImagePreviewUrl(reader.result);
    };

    if (file) {
      reader.readAsDataURL(file);
    }
  };

  const removeImages = (imageName) => {
    const resultFileNames = product.uploadFileNames.filter(
      (fileName) => fileName !== imageName
    );
    product.uploadFileNames = resultFileNames;

    setProduct({ ...product });
  };

  const handleClickModify = () => {
    const files = uploadRef.current.files;
    const formData = new FormData();

    for (let i = 0; i < files.length; i++) {
      formData.append("files", files[i]);
    }

    // other data
    formData.append("pname", product.pname);
    formData.append("pdesc", product.pdesc);
    formData.append("price", product.price);
    formData.append("delFlag", product.delFlag);

    for (let i = 0; i < product.uploadFileNames.length; i++) {
      formData.append("uploadFileNames", product.uploadFileNames[i]);
    }

    setLoading(true);

    putOne(pno, formData).then((data) => {
      setResult("Modified");
      setLoading(false);
    });
  };

  const handleClickDelete = () => {
    setLoading(true);
    deleteOne(product).then((data) => {
      setResult("Deleted");
      setLoading(false);
    });
  };

  const closeAlertModal = () => {
    if (result === "Modified") {
      moveReadPage(pno);
    } else if (result === "Deleted") {
      moveProoductListPage({ page: 1 });
    }

    setResult(null);
  };

  return (
    <div className="modify_group">
      <div>상품 수정</div>
      {loading ? <LoadingModal /> : <></>}
      {result ? (
        <AlertModal
          title={`${result}`}
          content={"정상적으로 처리되었습니다."} //결과 모달창
          callbackFn={closeAlertModal}
        />
      ) : (
        <></>
      )}
      <div className="modify_container">
        {/* 상품 이미지 영역 */}
        <div className="modify_area modify_imgArea">
          <div className="modify_imgRemove">
            <div className="modify_wrap">
              <div className="modify-info">현재 이미지</div>
              <div className="modify-content">
                {product.uploadFileNames.map((imgFile, i) => (
                  <div className="modify-box current" key={i}>
                    <div className="imageContainer">
                      <img
                        alt={product.pname}
                        src={`${host}/api/products/view/s_${imgFile}`}
                      />
                      <button
                        className="imgRemoveBtn"
                        onClick={() => removeImages(imgFile)}
                      >
                        X
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
          <div className="modify_imgAdd">
            <div className="modify_wrap">
              <div className="image_upload_preview">
                {imagePreviewUrl ? (
                  <img
                    src={imagePreviewUrl}
                    className="addImage"
                    alt="preview"
                  />
                ) : (
                  <label htmlFor="uploadImage">파일 선택</label>
                )}
                <input
                  ref={uploadRef}
                  id="uploadImage"
                  type="file"
                  multiple={true}
                  onChange={handleImageChange}
                  style={{ display: "none" }}
                  alt={product.pname}
                />
              </div>
            </div>
          </div>
        </div>
        {/* 상품 상세 영역 */}
        <div className="modify_textArea">
          <div className="modify-wrap relative mb-4 flex w-full flex-wrap items-stretch">
            <div className="modify-info w-1/5 p-6 text-right font-bold">
              상품명
            </div>
            <input
              className="w-4/5 p-6 rounded-r border border-solid border-neutral-300 shadow-md"
              name="pname"
              type={"text"}
              value={product.pname}
              onChange={handleChangeProduct}
            ></input>
          </div>
          <div className="modify-wrap flex justify-center">
            <div className="modify-box relative mb-4 flex w-full flex-wrap items-stretch">
              <div className="modify-info w-1/5 p-6 text-right font-bold">
                상품 상세
              </div>
              <textarea
                className="w-4/5 p-6 rounded-r border border-solid border-neutral-300 shadow-md resize-y"
                name="pdesc"
                rows="4"
                onChange={handleChangeProduct}
                value={product.pdesc}
              >
                {product.pdesc}
              </textarea>
            </div>
          </div>
          <div className="modify-wrap flex justify-center">
            <div className="modify-box relative mb-4 flex w-full flex-wrap items-stretch">
              <div className="modify-info w-1/5 p-6 text-right font-bold">
                판매가
              </div>
              <input
                className="w-4/5 p-6 rounded-r border border-solid border-neutral-300 shadow-md"
                name="price"
                type={"text"}
                value={formattedPrice}
                onChange={handleChangeProduct}
              ></input>
            </div>
          </div>
          <div className="modify-wrap flex justify-center">
            <div className="modify-box relative mb-4 flex w-full flex-wrap items-stretch">
              <div className="modify-info w-1/5 p-6 text-right font-bold">
                삭제 여부
              </div>
              <select
                name="delFlag"
                value={product.delFlag}
                onChange={handleChangeProduct}
                className="w-4/5 p-6 rounded-r border border-solid border-neutral-300 shadow-md"
              >
                <option value={false}>유효함</option>
                <option value={true}>삭제됨</option>
              </select>
            </div>
          </div>
        </div>
      </div>
      {/* 버튼 영역 */}
      <div className="shopModify_btn">
        <button
          type="button"
          className="shopModify_deleteBtn"
          onClick={handleClickDelete}
        >
          삭제
        </button>

        <button
          type="button"
          className="shopModify_modifyBtn"
          onClick={handleClickModify}
        >
          수정
        </button>

        <button
          type="button"
          className="shopModify_listBtn"
          onClick={moveProoductListPage}
        >
          목록
        </button>
      </div>
    </div>
  );
};

export default ModifyComponent_p;
