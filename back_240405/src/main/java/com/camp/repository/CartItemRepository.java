package com.camp.repository;

import java.util.List;

import com.camp.domain.Cart;
import com.camp.domain.CartItem;
import com.camp.dto.CartItemListDTO;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface CartItemRepository extends JpaRepository<CartItem, Long>{

    // 회원의 이메일을 기반으로 해당 회원의 카트 아이템 목록을 조회하는 쿼리 메서드
    @Query("select " +
            " new com.camp.dto.CartItemListDTO(ci.cino,  ci.qty,  p.pno, p.pname, p.price , pi.fileName )  " +
            " from " +
            "   CartItem ci inner join Cart mc on ci.cart = mc " +
            "   left join Product p on ci.product = p " +
            "   left join p.imageList pi" +
            " where " +
            "   mc.owner.email = :email and pi.ord = 0 " +
            " order by ci desc ")
    public List<CartItemListDTO> getItemsOfCartDTOByEmail(@Param("email") String email);

    // 회원의 이메일과 상품 번호를 기반으로 해당 회원의 해당 상품의 카트 아이템을 조회하는 쿼리 메서드
    @Query("select" +
            " ci "+
            " from " +
            "   CartItem ci inner join Cart c on ci.cart = c " +
            " where " +
            "   c.owner.email = :email and ci.product.pno = :pno")
    public CartItem getItemOfPno(@Param("email") String email, @Param("pno") Long pno );

    // 카트 아이템 번호를 기반으로 해당 카트 아이템의 카트 번호를 조회하는 쿼리 메서드
    @Query("select " +
            "  c.cno " +
            "from " +
            "  Cart c inner join CartItem ci on ci.cart = c " +
            " where " +
            "  ci.cino = :cino")
    public Long getCartFromItem( @Param("cino") Long cino);

    // 카트 번호를 기반으로 해당 카트의 카트 아이템 목록을 조회하는 쿼리 메서드
    @Query("select new com.camp.dto.CartItemListDTO(ci.cino,  ci.qty,  p.pno, p.pname, p.price , pi.fileName )  " +
            " from " +
            "   CartItem ci inner join Cart mc on ci.cart = mc " +
            "   left join Product p on ci.product = p " +
            "   left join p.imageList pi" +
            " where " +
            "  mc.cno = :cno and pi.ord = 0 " +
            " order by ci desc ")

    public List<CartItemListDTO> getItemsOfCartDTOByCart(@Param("cno") Long cno);


}
