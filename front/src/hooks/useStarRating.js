import { useCallback, useState } from "react";

const useStarRating = (initialRating = 0) => {
  const [rating, setRating] = useState(initialRating);

  const handleRating = useCallback((newRating) => {
    setRating(newRating);
  }, []);

  return [rating, handleRating];
};

export default useStarRating;
