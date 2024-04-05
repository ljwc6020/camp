package com.camp.repository;

import com.camp.domain.NoticeBoard;
import com.camp.domain.Product;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;


public interface NoticeBoardRepository extends JpaRepository<NoticeBoard, Long> {

    @EntityGraph(attributePaths = "boardImageList")
    @Query("select nb from NoticeBoard nb where nb.nbno = :nbno")
    Optional<NoticeBoard> selectOne(@Param("nbno") Long nbno);

    @Query("select n, ni from NoticeBoard n left join n.boardImageList ni " +
            "where (n.title like %:title% or :title is null) and (n.writer like %:writer% or :writer is null)")
    Page<Object[]> selectList(@Param("writer") String writer, @Param("title") String title, Pageable pageable);
}
