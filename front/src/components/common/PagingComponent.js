import "../../styles/components/pagingComponent.scss";

const PagingComponent = ({ serverData, movePage }) => {
  return (
    <div className="paging_wrap">
      {serverData.prev ? (
        <div
          className="paging_box"
          onClick={() => movePage({ page: serverData.prevPage })}
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
          onClick={() => movePage({ page: pageNum })}
        >
          {pageNum}
        </div>
      ))}

      {serverData.next ? (
        <div
          className="paging_box"
          onClick={() => movePage({ page: serverData.nextPage })}
        >
          ▶
        </div>
      ) : (
        <></>
      )}
    </div>
  );
};

export default PagingComponent;
