import { FaStar, FaStarHalf } from "react-icons/fa";
import "../../../styles/components/starRating.scss";

const StarInput = ({ onClickRating, value, isHalf }) => {
  const handleClickRatingInput = () => {
    onClickRating(value);
  };

  return (
    <>
      <input
        className="input"
        type="radio"
        name="rating"
        id={`star${value}`}
        value={value}
      />
      <label
        className={`label ${isHalf ? "isHalf" : ""}`}
        onClick={handleClickRatingInput}
        htmlFor={`star${value}`}
      >
        {isHalf ? <FaStarHalf /> : <FaStar />}
      </label>
    </>
  );
};

export default StarInput;
