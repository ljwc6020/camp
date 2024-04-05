import { useEffect, useState } from "react";
import useCustomMovePage from "../../hooks/useCustomMovePage";
import { getOne } from "../../api/productApi";
import { API_SERVER_HOST } from "../../api/userApi";
import useCustomCartPage from "../../hooks/useCustomCartPage";
import useCustomLoginPage from "../../hooks/useCustomLoginPage";
import "../../styles/components/readComponent.scss";
import { useNavigate } from "react-router-dom";
import { formatNumber } from "../../util/formatNumberUtil";
import { getReviewList } from "../../api/productReviewApi";
import CartModal from "../modal/CartModal";
import StarDisplay from "../common/star/StarDisplay";
import ImageModal from "../modal/ImageModal";
import LoadingModal from "../modal/LoadingModal";

const initState = {
  pname: "",
  pdesc: "",
  price: 0,
  uploadFileNames: [],
};

const host = API_SERVER_HOST;

const ReadComponent_p = ({ pno }) => {
  const [product, setProduct] = useState(initState);
  const { moveProoductListPage, moveModifyPage } = useCustomMovePage();
  const { changeCart, cartItems } = useCustomCartPage();
  const navigate = useNavigate();
  const [quantity, setQuantity] = useState(1);
  const [cartModal, setCartModal] = useState(false);
  const [totalPrice, setTotalPrice] = useState(product.price);
  const [averageRating, setAverageRating] = useState(0);
  const [openImg, setOpenImg] = useState(false);
  const [selectedImgPath, setSelectedImgPath] = useState("");
  const { isAdmin, loginState } = useCustomLoginPage();
  const [loading, setLoading] = useState(false);

  const handleClickPayment = () => {
    navigate("/payment", {
      state: {
        productName: product.pname,
        productPrice: product.price,
        productId: pno,
        quantity: quantity,
      },
    });
    window.location.reload();
  };

  useEffect(() => {
    setLoading(true);

    getOne(pno).then((data) => {
      console.log(data);
      setProduct(data);
      window.scrollTo(0, 0);
      setLoading(false);
    });
  }, [pno]);

  const handleClickAddCart = () => {
    const addedItem = cartItems.find((item) => item.pno === parseInt(pno));
    if (addedItem) {
      if (!window.confirm("이미 추가된 상품입니다. 추가하시겠습니까?")) {
        return;
      }
      changeCart({
        email: loginState.email,
        pno: pno,
        qty: addedItem.qty + quantity,
      });
    } else {
      changeCart({ email: loginState.email, pno: pno, qty: quantity });
    }
    setCartModal(true);
  };

  const handleQuantityInput = (event) => {
    const inputQuantity = event.target.value;
    // 숫자가 아닌 입력값을 걸러냅니다.
    const quantityNumber = parseInt(inputQuantity, 10);

    if (!isNaN(quantityNumber) && quantityNumber > 0) {
      setQuantity(quantityNumber);
    } else {
      // 유효하지 않은 입력이 들어오면 수량을 1로 설정
      setQuantity(1);
    }
  };

  const increaseQty = () => {
    setQuantity((prevQuantity) => prevQuantity + 1);
  };
  const decreaseQty = () => {
    setQuantity((prevQuantity) => (prevQuantity > 1 ? prevQuantity - 1 : 1));
  };

  useEffect(() => {
    setTotalPrice(product.price * quantity);
  }, [quantity, product.price]);

  const moveCartPage = () => {
    navigate("/product/cart");
    setCartModal(false);
  };
  const closeCartModal = () => {
    setCartModal(false);
  };

  useEffect(() => {
    getReviewList({ page: 1, size: 10 }, pno).then((data) => {
      const reviews = data.dtoList || [];
      const totalRating = reviews.reduce(
        (acc, review) => acc + review.score,
        0
      );
      const avgRating = reviews.length > 0 ? totalRating / reviews.length : 0;
      setAverageRating(Math.round(avgRating * 10) / 10);
    });
  }, [pno]);

  const handleOpenImg = (imgFile) => {
    setSelectedImgPath(`${host}/review/view/${imgFile}`);
    setOpenImg(true);
  };

  const closeImageModal = () => {
    setOpenImg(false);
  };

  return (
    <div className="shopRead_group">
      {loading ? <LoadingModal /> : <></>}
      {cartModal && (
        <CartModal
          closeCartModal={closeCartModal}
          moveCartPage={moveCartPage}
        />
      )}
      {/* 상품 영역 */}
      <div className="shopRead_img">
        {product.uploadFileNames.map((imgFile, i) => (
          <img
            alt="product"
            key={i}
            src={`${host}/api/products/view/${imgFile}`}
            onClick={() => handleOpenImg(imgFile)}
          />
        ))}
      </div>
      {openImg && (
        <ImageModal
          openImg={openImg}
          callbackFn={closeImageModal}
          imagePath={selectedImgPath}
        />
      )}
      <div className="shopRead_details">
        <div className="shopRead_area">
          <div className="shopRead_wrap">
            <div className="shopRead_box">
              <div className="shopRead_pdesc">{product.pdesc}</div>
              <div className="shopRead_averageRating">
                <StarDisplay score={averageRating} />
                &nbsp;&nbsp;{averageRating / 2}점
              </div>
            </div>
          </div>
          <div className="shopRead_wrap">
            <div className="shopRead_box">
              <div className="shopRead_pname">{product.pname}</div>
            </div>
          </div>
          <div>
            <div className="shopRead-pno">상품 번호: {product.pno}</div>
          </div>
        </div>
        <div className="shopRead_area">
          <div className="shopRead_wrap">
            <div className="shopRead_box">
              <div className="shopRead_info">판매가</div>
              <div className="shopRead_price">
                {formatNumber(product.price)}원
              </div>
            </div>
          </div>
          {/* 수량 조절 버튼 */}
          <div className="shopRead_wrap quantity_control">
            <div className="shopRead_info">구매 수량:</div>
            <div className="shopRead_qty">
              <input
                type="text"
                className="quantity_display"
                value={quantity}
                onChange={handleQuantityInput}
                min="1" // 최소 수량을 1로 설정합니다.
              />
              <button className="quantity_button" onClick={decreaseQty}>
                -
              </button>
              <button className="quantity_button" onClick={increaseQty}>
                +
              </button>
            </div>
          </div>
          {/* 동적으로 변하는 가격 */}
          <div className="shopRead_wrap total_price">
            <div className="">TOTAL</div>
            <div className="shopRead_totalPrice">
              {formatNumber(totalPrice)}원
            </div>
          </div>
        </div>
        <div className="shopRead_area">
          {/* 버튼 영역 */}
          <div className="shopRead_btn">
            <button
              type="button"
              className="shopRead_addBtn"
              onClick={handleClickAddCart}
            >
              장바구니 담기
            </button>
            <button
              type="button"
              className="shopRead_paymentBtn"
              onClick={handleClickPayment}
            >
              바로 구매하기
            </button>
            <button
              type="button"
              className="shopRead_listBtn"
              onClick={moveProoductListPage}
            >
              목록
            </button>
            {isAdmin && (
              <button
                type="button"
                className="shopRead_modifyBtn"
                onClick={() => moveModifyPage(pno)}
              >
                수정
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default ReadComponent_p;
