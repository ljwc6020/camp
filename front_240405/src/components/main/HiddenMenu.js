import { Link } from "react-router-dom";

function HiddenMenu({ isActive }) {
  return (
    <div className={`gnb-box ${isActive ? "active" : ""}`}>
      <ul className="gnb-m">
        <li>
          <Link to={"/camping"}>캠핑장</Link>
        </li>
        <li>
          <Link to={"/product"}>쇼핑몰</Link>
        </li>
        <li>
          <Link to={"/noticeboard"}>공지사항</Link>
        </li>
      </ul>
    </div>
  );
}

export default HiddenMenu;

//기존 코드
// const HiddenMenu = () => {
//   const ham = document.querySelector(".btn-ham");
//   const box = document.querySelector(".gnb-box");

//   ham.addEventListener("click", () => {
//     box.classList.toggle("active");
//   });
// };

// export default HiddenMenu;
