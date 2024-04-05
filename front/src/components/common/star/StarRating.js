import StarInput from "./StarInput";
import "../../../styles/components/starRating.scss";

const StarRating = ({ rating, onRatingChange }) => {
  const handleClickRating = (value) => {
    onRatingChange(value);
  };

  return (
    <div className="base">
      <div className="ratingField">
        <StarInput
          onClickRating={() => handleClickRating(5)}
          value={5}
          isHalf={false}
        />
        <StarInput
          onClickRating={() => handleClickRating(4.5)}
          value={4.5}
          isHalf={true}
        />
        <StarInput
          onClickRating={() => handleClickRating(4)}
          value={4}
          isHalf={false}
        />
        <StarInput
          onClickRating={() => handleClickRating(3.5)}
          value={3.5}
          isHalf={true}
        />
        <StarInput
          onClickRating={() => handleClickRating(3)}
          value={3}
          isHalf={false}
        />
        <StarInput
          onClickRating={() => handleClickRating(2.5)}
          value={2.5}
          isHalf={true}
        />
        <StarInput
          onClickRating={() => handleClickRating(2)}
          value={2}
          isHalf={false}
        />
        <StarInput
          onClickRating={() => handleClickRating(1.5)}
          value={1.5}
          isHalf={true}
        />
        <StarInput
          onClickRating={() => handleClickRating(1)}
          value={1}
          isHalf={false}
        />
        <StarInput
          onClickRating={() => handleClickRating(0.5)}
          value={0.5}
          isHalf={true}
        />
      </div>
      <div className="ratingValue">{rating}</div>
    </div>
  );
};

export default StarRating;
