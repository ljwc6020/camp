import React, { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { getList } from "../api/productApi";
import "../styles/pages/mainPage.scss";
import BasicLayout from "../layouts/BasicLayout";
import C1 from "../img/camping1.jpg";
import C2 from "../img/camping2.jpg";
import C3 from "../img/camping3.jpg";
import C4 from "../img/camping4.png";
import $ from "jquery";
import ImageComponent from "../components/image/Imagecomponent";
import { API_SERVER_HOST } from "../api/userApi";

const host = API_SERVER_HOST;

function MainPage() {
  const [keyword, setKeyword] = useState(""); // 입력값 상태 변수 추가
  const navigate = useNavigate(); // useNavigate 훅 호출

  useEffect(() => {
    // tab
    const menu = document.querySelectorAll(".menu li");
    const cont = document.querySelectorAll(".content li");

    menu.forEach((menuItem, index) => {
      menuItem.addEventListener("click", () => {
        menu.forEach((menuItem2) => {
          menuItem2.classList.remove("active");
        });
        menuItem.classList.add("active");
        cont.forEach((contItem, contIndex) => {
          if (index === contIndex) {
            contItem.classList.add("active");
          } else {
            contItem.classList.remove("active");
          }
        });
      });
    });

    // slide JQ
    $(".btn-prev").click(function () {
      let width = $(".slide li:last-child").width();
      let slide = $(".slide ul");
      if (slide.is(":animated") === false) {
        $(slide).prepend($(".slide li:last"));
        $(slide).css("left", -width);

        $(slide).animate({ left: "0px" }, 1000);
      }
    });

    $(".btn-next").click(function () {
      let width = $(".slide li:first-child").width();
      let slide = $(".slide ul");

      if (slide.is(":animated") === false) {
        $(slide).animate({ left: -width }, 1000, function () {
          $(slide).append($(".slide li:first"));
          $(slide).css("left", "0px");
        });
      }
    });
  }, []);

  // moveSlide
  useEffect(() => {
    const intervalId = setInterval(() => {
      // 다음 슬라이드로 이동하는 함수 호출
      moveSlide();
    }, 5000); // 5초마다 슬라이드를 변경합니다.

    // 컴포넌트가 unmount 될 때 interval 정리
    return () => clearInterval(intervalId);
  }, []);

  // 슬라이드를 변경하는 함수
  function moveSlide() {
    let width = $(".slide li:first-child").width();
    let slide = $(".slide ul");

    if (slide.is(":animated") === false) {
      $(slide).animate({ left: -width }, 1000, function () {
        $(slide).append($(".slide li:first"));
        $(slide).css("left", "0px");
      });
    }
  }

  const handleSearch = (e) => {
    e.preventDefault();
    // 제출된 값과 함께 원하는 경로로 이동
    navigate(`/camping?keyword=${keyword}`);
  };

  const handleChange = (e) => {
    setKeyword(e.target.value); // 입력 값을 업데이트
  };

  const handleKeyPress = (e) => {
    if (e.key === "Enter") {
      handleSearch(e);
    }
  };

  // 메인 페이지에 가장 최근 상품 4개 가져오는 메서드
  const [recentProducts, setRecentProducts] = useState([]);
  useEffect(() => {
    getList({ page: 1, size: 4 }).then((data) => {
      setRecentProducts(data.dtoList);
    });
  }, []);

  return (
    <BasicLayout>
      <div className="wrap">
        <section className="main1_bg">
          <div className="main1">
            <div className="tab-box">
              <ul className="menu">
                <li className="active">이미지 검색</li>
                <li>일반 검색</li>
              </ul>
              <ul className="content">
                <li className="active">
                  <div className="upload">
                    <ImageComponent />
                  </div>
                </li>
                <li>
                  <input
                    type="text"
                    placeholder="여행지를 입력하세요"
                    value={keyword}
                    onChange={handleChange}
                    onKeyPress={handleKeyPress}
                  />
                  <button onClick={handleSearch}>검색</button>
                </li>
              </ul>
            </div>
            <div className="slide-section">
              <h2>이 달의 캠핑장</h2>
              <div className="slide">
                <ul>
                  <li>
                    <Link to="http://outofpark.com/main/">
                      <img src={C1} alt="캠핑장1" />
                    </Link>
                  </li>
                  <li>
                    <Link to=" http://www.healpoint.co.kr/index.php">
                      <img src={C2} alt="캠핑장2" />
                    </Link>
                  </li>
                  <li>
                    <Link to="http://badadacamp.co.kr/index.html">
                      <img src={C3} alt="캠핑장3" />
                    </Link>
                  </li>
                </ul>
                <div className="btn-box">
                  <button className="btn-prev">◀</button>
                  <button className="btn-next">▶</button>
                </div>
              </div>
            </div>
          </div>
        </section>
        <section className="main2_bg">
          <span className="main2_title">HOT 캠핑 아이템</span>
          <ul className="main2">
            {recentProducts.map((product) => (
              <li key={product.pno}>
                <Link to={`/product/read/${product.pno}`}>
                  <div className="mainProduct_thum">
                    <img
                      src={`${host}/api/products/view/s_${product.uploadFileNames[0]}`}
                      alt={product.pname}
                    />
                  </div>
                  <span>{product.pname}</span>
                </Link>
              </li>
            ))}
          </ul>
        </section>
        <section className="main3_bg">
          <div className="main3">
            <div className="left">
              <iframe
                width="1004"
                height="565"
                src="https://www.youtube.com/embed/R0sklBTfwO0"
                title="설악산 봉정암 대중교통 당일치기 / 봉정암 미역국"
                frameborder="0"
                allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share"
                allowfullscreen
              ></iframe>
            </div>
            <div className="right">
              <p>설악산 봉정암(鳳頂庵)</p>
              <div>
                대한불교조계종 제3교구인 백담사(百潭寺)의 부속암자이며, <br />
                대표적 불교 성지인 5대적멸보궁(五大寂滅寶宮) 중의 하나로 <br />
                불교신도들의 순례지로도 유명하다. <br />
                <br />
                643년(선덕여왕 12)에 자장(慈藏)이 당나라에서 부처님의 <br />
                진신사리(眞身舍利)를 가지고 귀국하여, <br />
                이곳에서 사리를 봉안하고 창건하였다. 그 뒤 677년(문무왕 17)에
                <br />
                원효(元曉)가, 1188년(명종 18)에 지눌(知訥)이 중건하였으며,
                <br />
                1518년(중종 13)에 환적(幻寂)이 중수하였다.
              </div>
              <ul>
                <li>
                  <Link to={"http://www.oasisjungle.com/"}>
                    <img src={C3} alt="오아시스 정글" />
                    <span>오아시스 정글</span>
                  </Link>
                </li>
                <li>
                  <Link to={"https://vivaldicamping.com/"}>
                    <img src={C4} alt="비발디 캠핑 파크" />
                    <span>비발디 캠핑 파크</span>
                  </Link>
                </li>
              </ul>
            </div>
          </div>
        </section>
      </div>
    </BasicLayout>
  );
}

export default MainPage;
