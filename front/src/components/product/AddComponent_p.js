import { useRef, useState } from "react";
import { postOne } from "../../api/productApi";
import useCustomMovePage from "../../hooks/useCustomMovePage";
import AlertModal from "../modal/AlertModal";
import LoadingModal from "../modal/LoadingModal";
import "../../styles/components/addComponent.scss";

const initState = {
  pname: "",
  pdesc: "",
  price: "",
  files: [],
};

const AddComponent_p = () => {
  const [product, setProduct] = useState({ ...initState });
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const { moveProoductListPage } = useCustomMovePage();
  const [imagePreviewUrl, setImagePreviewUrl] = useState("");

  const uploadRef = useRef();

  const handleChangeProduct = (e) => {
    let { name, value } = e.target;
    if (name === "price") {
      // 가격 콤마 표시 후 숫자만 반환
      value = value.replace(/[^\d]/g, "").replace(/\B(?=(\d{3})+(?!\d))/g, ",");
    }
    setProduct({
      ...product,
      [name]: value,
    });
  };

  // // 이미지 등록 시 미리보기 생성
  const handleImagePreview = (e) => {
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

  const handleClickAdd = (e) => {
    const files = uploadRef.current.files;

    const formData = new FormData();

    for (let i = 0; i < files.length; i++) {
      formData.append("files", files[i]);
    }

    //other data
    formData.append("pname", product.pname);
    formData.append("pdesc", product.pdesc);
    formData.append("price", product.price.replace(/[^\d]/g, ""));

    console.log(formData);

    setLoading(true);

    postOne(formData).then((data) => {
      setLoading(false);
      setResult(data.result);
      setProduct({ ...initState });
    });
  };

  const closeAlertModal = () => {
    setResult(null);
    moveProoductListPage({ page: 1 });
  };

  return (
    <div className="add_group">
      <div>상품 등록</div>
      {loading ? <LoadingModal /> : <></>}
      {result ? (
        <AlertModal
          title={"상품이 등록되었습니다."}
          content={`${result}번 상품 등록 완료`}
          callbackFn={closeAlertModal}
        />
      ) : (
        <></>
      )}
      <div className="add_container">
        {/* 상품 이미지 영역 */}
        <div className="add_area add_imgArea">
          <div className="add_wrap">
            <div className="image_upload_preview">
              {imagePreviewUrl ? (
                <img
                  src={imagePreviewUrl}
                  className="addImage"
                  alt={product.pname}
                />
              ) : (
                <label htmlFor="uploadImage">파일 선택</label>
              )}
              <input
                ref={uploadRef}
                id="uploadImage"
                type="file"
                multiple={true}
                onChange={handleImagePreview}
              />
            </div>
          </div>
        </div>
        {/* 상품 상세 영역 */}
        <div className="add_textArea">
          <div className="add_area">
            <div className="add_wrap">
              <div className="add_box">상품명</div>
              <textarea
                className=""
                name="pname"
                type={"text"}
                value={product.pname}
                onChange={handleChangeProduct}
              ></textarea>
            </div>
          </div>
          <div className="add_area">
            <div className="add_wrap">
              <div className="add_box">상품 상세</div>
              <textarea
                className=""
                name="pdesc"
                type={"text"}
                onChange={handleChangeProduct}
                value={product.pdesc}
              ></textarea>
            </div>
          </div>
          <div className="add_area">
            <div className="add_wrap">
              <div className="add_box">상품 가격</div>
              <input
                className=""
                name="price"
                type={"text"}
                value={product.price}
                onChange={handleChangeProduct}
              ></input>
            </div>
          </div>
        </div>
      </div>
      {/* 버튼 영역 */}
      <div className="shopList_btn">
        <button
          type="button"
          className="shopList_addBtn"
          onClick={handleClickAdd}
        >
          상품 등록
        </button>
      </div>
    </div>
  );
};

export default AddComponent_p;
