import { useDispatch, useSelector } from "react-redux";
import { getCartItemsAsync, postCartItemsAsync } from "../slices/cartSlice";

const useCustomCartPage = () => {
  const cartItems = useSelector((state) => state.cartSlice);
  const dispatch = useDispatch();
  const refreshCart = () => {
    dispatch(getCartItemsAsync());
  };

  const changeCart = (param) => {
    dispatch(postCartItemsAsync(param));
  };

  return { cartItems, refreshCart, changeCart };
};

export default useCustomCartPage;
