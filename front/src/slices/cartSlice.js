import { createAsyncThunk, createSlice } from "@reduxjs/toolkit";
import { getCartItems, postCartItems } from "../api/cartApi";

export const getCartItemsAsync = createAsyncThunk("getCartItemsAsync", () => {
  return getCartItems();
});

export const postCartItemsAsync = createAsyncThunk(
  "postCartItemsAsync",
  (param) => {
    return postCartItems(param);
  }
);

const initState = [];

const cartSlice = createSlice({
  name: "cartSlice",
  initialState: initState,
  extraReducers: (builder) => {
    builder
      .addCase(getCartItemsAsync.fulfilled, (state, action) => {
        console.log("getCartItemsAsync fulfilled");
        return action.payload;
      })
      .addCase(postCartItemsAsync.fulfilled, (state, action) => {
        console.log("postCartItemsAsync fulfilled");
        return action.payload;
      });
  },
});

export default cartSlice.reducer;
