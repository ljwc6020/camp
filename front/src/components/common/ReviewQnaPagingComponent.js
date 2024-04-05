import "../../styles/components/pagingComponent.scss";

const ReviewQnaPagingComponent = ({ serverData, movePage }) => {
  return (
    <div className="paging_wrap">
      {serverData.prev ? (
        <div
          className="paging_box"
          onClick={() => movePage({ reviewQnaPage: serverData.prevPage })}
        >
          ◀
        </div>
      ) : (
        <></>
      )}

      {serverData.pageNumList.map((pageNum) => (
        <div
          key={pageNum}
          className={`paging_box ${
            serverData.current === pageNum ? "now" : ""
          }`}
          onClick={() => movePage({ reviewQnaPage: pageNum })}
        >
          {pageNum}
        </div>
      ))}

      {serverData.next ? (
        <div
          className="paging_box"
          onClick={() => movePage({ reviewQnaPage: serverData.nextPage })}
        >
          ▶
        </div>
      ) : (
        <></>
      )}
    </div>
  );
};

export default ReviewQnaPagingComponent;
