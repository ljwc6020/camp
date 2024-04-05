import { FaStar, FaStarHalf, FaRegStar } from "react-icons/fa";
import "../../../styles/components/starRating.scss";

const StarDisplay = ({ score }) => {
  const fullStars = Math.floor(score / 2); // 전체 별의 개수
  const halfStar = score % 2 ? 1 : 0; // 반 별이 필요한지
  const emptyStars = 5 - fullStars - halfStar; // 비어있는 별의 개수

  return (
    <div className="starDisplay">
      {[...Array(fullStars)].map((_, index) => (
        <FaStar key={index} className="faStar" />
      ))}
      {halfStar ? <FaStarHalf className="faStarHalf" /> : null}
      {[...Array(emptyStars)].map((_, index) => (
        <FaRegStar key={index} className="faRegStar" />
      ))}
    </div>
  );
};

export default StarDisplay;
